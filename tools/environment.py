"""Decide whether each server is Production or Development.

Sources, strongest first:
1. reference/environment_overrides.csv  (maintained by the team, by IP or by application)
2. the AI Platforms Inventory (the reference for AI platform servers)
3. the application name in the latest reports (Prod / DR / NonProd / Dev / SIT / UAT ...)
4. the team server list (MS_All_servers.xlsx, column "Enviroment")
5. the safe default from guardrails/policies.yaml (Production)

The latest reports are the reference: when the application name states the environment, it
wins over the older server list (a server listed as Development that belongs to
"CEM Kafka Prod" is Production). The server list only decides when the name says nothing.

Pre-production, test, SIT and UAT count as Development: they may be changed at any time.
Disaster-recovery sites count as Production.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

PROD = "Production"
DEV = "Development"

SRC_OVERRIDE = "Override file"
SRC_INVENTORY = "AI inventory"
SRC_SERVER_LIST = "Server list"
SRC_APP_NAME = "Application name"
SRC_ASSUMED = "Assumed"

_NON_PROD = re.compile(
    r"non[\s_\-]?prod|pre[\s_\-]?prod|preprod|\bdev\b|\bdev[\s_\-]|[\s_\-]dev\b|development|\bsit\b|\buat\b"
    r"|\btest|staging|sandbox|\bpoc\b|\blab\b",
    re.IGNORECASE,
)
_PROD = re.compile(r"prod|\bdr\b|[\s_\-]dr[\s_\-(]|\(dr\)", re.IGNORECASE)

OVERRIDE_COLUMNS = ["Device Name", "Applications", "Environment"]


def environment_from_name(application: str | None) -> str | None:
    """Guess the environment from an application name; None when the name says nothing."""
    text = str(application or "")
    if _NON_PROD.search(text):
        return DEV
    if _PROD.search(text):
        return PROD
    return None


def _normalise(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if text.startswith("prod"):
        return PROD
    if text.startswith(("dev", "non", "pre", "test", "uat", "sit")):
        return DEV
    return None


SERVER_LIST_COLUMNS = ["IP", "Application", "Cluster", "Environment", "Hostname"]


class ReferenceFileError(ValueError):
    """The server list or the override file exists but cannot be used."""


def load_server_list(path: Path) -> pd.DataFrame:
    """Read the team inventory. Returns columns IP, Application, Cluster, Environment, Hostname."""
    if not path.exists():
        return pd.DataFrame(columns=SERVER_LIST_COLUMNS)
    frame = pd.read_excel(path)
    frame = frame.rename(columns={"Enviroment": "Environment"})  # spelling used in the inventory file
    missing = [column for column in ("IP", "Environment") if column not in frame.columns]
    if missing:
        raise ReferenceFileError(f"{path.name} has no {' or '.join(missing)} column "
                                 f"(found: {', '.join(map(str, frame.columns[:10]))})")
    frame = frame.loc[:, [c for c in SERVER_LIST_COLUMNS if c in frame.columns]].dropna(subset=["IP"])
    frame["IP"] = frame["IP"].astype(str).str.strip()
    return frame.drop_duplicates("IP")


def load_overrides(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=OVERRIDE_COLUMNS)
    frame = pd.read_csv(path, dtype=str, comment="#")
    if len(frame) and ("Environment" not in frame.columns
                       or not {"Device Name", "Applications"} & set(frame.columns)):
        raise ReferenceFileError(f"{path.name} needs the columns {', '.join(OVERRIDE_COLUMNS)} "
                                 f"(found: {', '.join(map(str, frame.columns))})")
    return frame.reindex(columns=OVERRIDE_COLUMNS).dropna(subset=["Environment"])


def save_overrides(path: Path, frame: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.reindex(columns=OVERRIDE_COLUMNS).to_csv(path, index=False)


def mapped_environment(overrides: pd.DataFrame, application: str, servers: list[str]) -> str | None:
    """The environment the override file gives these servers of one application, if they all agree."""
    same_app = overrides["Applications"].astype("string").str.strip().eq(application).fillna(False).astype(bool)
    app_rows = overrides[overrides["Device Name"].isna() & same_app]
    if not app_rows.empty:
        return _normalise(app_rows["Environment"].iloc[-1])
    by_ip = overrides.dropna(subset=["Device Name"])
    found = dict(zip(by_ip["Device Name"].str.strip(), by_ip["Environment"].map(_normalise)))
    values = {found.get(server) for server in servers}
    return values.pop() if len(values) == 1 else None


def remap_applications(overrides: pd.DataFrame, members: dict[str, list[str]],
                       chosen: dict[str, str | None]) -> pd.DataFrame:
    """Override rows after applications are mapped to an environment on the Settings page.

    ``members``: application -> the servers the page listed for it (no confirmed environment, or
    already set in the override file). ``chosen``: application -> new environment, or None to clear
    it, for the applications that changed. The mapping is written one row per listed server, so
    servers that the AI inventory, the application name or the server list already place keep their
    environment. An application-wide row of a changed application is replaced by those rows.
    """
    servers = {server for app in chosen for server in members.get(app, [])}
    device = overrides["Device Name"].astype("string").str.strip()
    applications = overrides["Applications"].astype("string").str.strip()
    replaced = device.isin(servers).fillna(False).astype(bool) | (device.isna() & applications.isin(list(chosen)).fillna(False).astype(bool))
    rows = [{"Device Name": server, "Applications": app, "Environment": environment}
            for app, environment in chosen.items() if environment for server in members.get(app, [])]
    parts = [frame for frame in (overrides[~replaced].reindex(columns=OVERRIDE_COLUMNS),
                                 pd.DataFrame(rows, columns=OVERRIDE_COLUMNS)) if not frame.empty]
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=OVERRIDE_COLUMNS)


def resolve_environments(
    devices: pd.DataFrame,
    server_list: pd.DataFrame,
    overrides: pd.DataFrame,
    default: str = PROD,
    inventory: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Return one row per device with Environment and Env Source.

    ``devices`` needs the columns "Device Name" and "Applications", and may have "Report Application":
    the name in the report before the AI inventory replaced it. The application-name rule reads that
    name, so an inventory server the inventory gives no environment is still placed by its report name.
    ``inventory`` is the AI Platforms Inventory (columns IP and Environment); servers it does not place
    fall through.
    """
    columns = ["Device Name", "Applications"] + (["Report Application"] if "Report Application" in devices else [])
    out = devices[columns].drop_duplicates("Device Name").copy()
    out["Environment"] = None
    out["Env Source"] = None

    def fill(values: pd.Series, source: str) -> None:
        mask = out["Environment"].isna() & values.notna()
        out.loc[mask, "Environment"] = values[mask]
        out.loc[mask, "Env Source"] = source

    by_ip = overrides.dropna(subset=["Device Name"])
    by_app = overrides[overrides["Device Name"].isna()].dropna(subset=["Applications"])
    fill(out["Device Name"].map(dict(zip(by_ip["Device Name"].str.strip(), by_ip["Environment"].map(_normalise)))),
         SRC_OVERRIDE)
    fill(out["Applications"].map(dict(zip(by_app["Applications"].str.strip(), by_app["Environment"].map(_normalise)))),
         SRC_OVERRIDE)
    if inventory is not None and not inventory.empty:
        fill(out["Device Name"].map(dict(zip(inventory["IP"], inventory["Environment"]))), SRC_INVENTORY)
    reported = (out["Report Application"].fillna(out["Applications"]) if "Report Application" in out
                else out["Applications"])
    names = {app: environment_from_name(app) for app in reported.dropna().unique()}
    fill(reported.map(names), SRC_APP_NAME)
    if not server_list.empty:
        fill(out["Device Name"].map(dict(zip(server_list["IP"], server_list["Environment"].map(_normalise)))),
             SRC_SERVER_LIST)

    assumed = out["Environment"].isna()
    out.loc[assumed, "Environment"] = default
    out.loc[assumed, "Env Source"] = SRC_ASSUMED
    return out[["Device Name", "Environment", "Env Source"]]
