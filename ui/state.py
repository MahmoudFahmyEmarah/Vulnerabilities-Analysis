"""Shared data for every page: load the reports once, enrich them, apply the sidebar filters."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import streamlit as st

import settings
from memory.knowledge_base import KnowledgeBase
from tools import classifier, data_loader as dl, environment as env, history, inventory as inv


@dataclass
class Data:
    vulns: pd.DataFrame
    mbss: pd.DataFrame
    cs: pd.DataFrame
    devices: pd.DataFrame                     # one row per server: environment, source, platform
    files: dict[str, Path | None]
    errors: dict[str, str] = field(default_factory=dict)
    team_ips: frozenset[str] = frozenset()
    inventory: pd.DataFrame = field(default_factory=pd.DataFrame)   # AI Platforms Inventory (reference)
    inventory_ips: frozenset[str] = frozenset()


def _signature(path: Path | None) -> tuple:
    if path is None or not path.exists():
        return ("missing",)
    stat = path.stat()
    return (str(path), stat.st_size, stat.st_mtime_ns)


@st.cache_resource(show_spinner=False, max_entries=6)
def _read(kind: str, signature: tuple) -> pd.DataFrame:
    return dl.LOADERS[kind](Path(signature[0]))


def _apply_inventory(frame: pd.DataFrame, inventory: pd.DataFrame) -> pd.DataFrame:
    """For servers in the AI Platforms Inventory, use its platform name as the application.

    The inventory is the reference, so its name replaces the report's. The report's own label is
    kept in "Report Application"; role and cluster come along as extra columns.
    """
    if frame.empty or inventory.empty:
        return frame
    by_ip = inventory.set_index("IP")
    platform = frame["Device Name"].map(by_ip["AI Platform"])
    out = frame.assign(**{
        "Report Application": frame["Applications"],
        "AI Platform": platform,
        "Server Role": frame["Device Name"].map(by_ip["Server Role"]),
        "Cluster": frame["Device Name"].map(by_ip["Cluster"]),
    })
    out["Applications"] = frame["Applications"].where(platform.isna(), platform)
    if "Host Name" in out.columns:
        out["Host Name"] = out["Host Name"].fillna(frame["Device Name"].map(by_ip["Hostname"]))
    return out


@st.cache_resource(show_spinner=False, max_entries=2)
def _enrich(signatures: tuple, overrides_sig: tuple, server_sig: tuple, config_sig: tuple, labels_sig: str,
            inventory_sig: tuple = ()) -> Data:
    """Load the three reports and add environment, SLA and topic columns. Cached until an input changes."""
    config, policies = settings.load_config(), settings.load_policies()
    files: dict[str, Path | None] = {}
    frames: dict[str, pd.DataFrame] = {}
    errors: dict[str, str] = {}
    for kind, signature in zip((dl.VULN, dl.MBSS, dl.CS), signatures):
        files[kind] = Path(signature[0]) if signature[0] != "missing" else None
        try:
            frames[kind] = _read(kind, signature) if files[kind] else pd.DataFrame()
        except dl.SchemaError as error:
            errors[kind], frames[kind] = str(error), pd.DataFrame()
        except Exception as error:  # noqa: BLE001 - show the problem instead of a stack trace
            errors[kind], frames[kind] = f"Could not read {files[kind].name}: {error}", pd.DataFrame()

    try:
        inventory = inv.load_inventory(settings.inventory_file(), config["app"].get("ai_inventory_names"))
    except Exception as error:  # noqa: BLE001 - a broken inventory file must not take the reports down
        errors["inventory"] = f"Could not read the AI Platforms Inventory: {error}"
        inventory = pd.DataFrame(columns=inv.COLUMNS)
    frames = {kind: _apply_inventory(frame, inventory) for kind, frame in frames.items()}

    server_list = _read_server_list(errors)
    device_columns = ["Device Name", "Applications", "Platform", "Report Application"]
    known = [f[[c for c in device_columns if c in f.columns]] for f in frames.values() if not f.empty]
    all_devices = (pd.concat(known).drop_duplicates("Device Name") if known
                   else pd.DataFrame(columns=device_columns[:3]))
    resolved = _resolve(all_devices, server_list, inventory, errors)
    devices = all_devices.merge(resolved, on="Device Name", how="left")
    team_ips = frozenset(server_list["IP"]) if not server_list.empty else frozenset()

    def with_environment(frame: pd.DataFrame) -> pd.DataFrame:
        if frame.empty:
            return frame
        return frame.merge(resolved, on="Device Name", how="left")

    vulns = with_environment(frames[dl.VULN])
    if not vulns.empty:
        vulns = dl.add_sla(vulns, config["sla_days"], int(config["sla_due_soon_days"]))
        topics = classifier.classify_titles(vulns["Title"], KnowledgeBase().topic_labels())
        vulns["Topic"], vulns["Topic Rule"] = topics["Topic"], topics["Topic Rule"]
        os_names = {name: classifier.os_family(name) for name in vulns["Operating System"].dropna().unique()}
        vulns["OS Family"] = vulns["Operating System"].map(os_names).fillna("Other / unknown")
    return Data(vulns, with_environment(frames[dl.MBSS]), with_environment(frames[dl.CS]), devices, files, errors,
                team_ips, inventory, frozenset(inventory["IP"]))


def _file_sig(path: Path) -> tuple:
    return (path.stat().st_mtime_ns,) if path.exists() else (0,)


def _labels_sig() -> str:
    """Fingerprint of the stored OS / application labels: changes when a label is added or changed, not only
    when their number does, so a relabelled title refreshes the cached data."""
    labels = sorted(KnowledgeBase().topic_labels().items())
    return hashlib.sha1(repr(labels).encode("utf-8")).hexdigest()


def load() -> Data:
    """Return the enriched data, reading the Excel files only when something changed."""
    with st.spinner("Reading the reports. The first read of a new file takes about half a minute."):
        found = dl.discover_files(settings.data_dir())   # newest report date first
        chosen = []
        for kind in (dl.VULN, dl.MBSS, dl.CS):
            picked = st.session_state.get(f"file::{kind}")
            options = found[kind]
            path = next((p for p in options if p.name == picked), options[0] if options else None)
            chosen.append(_signature(path))
        arguments = (tuple(chosen), _file_sig(settings.overrides_file()), _file_sig(settings.server_list_file()),
                     _file_sig(settings.CONFIG_FILE) + _file_sig(settings.POLICIES_FILE), _labels_sig(),
                     _file_sig(settings.inventory_file()) if settings.inventory_file() else ())
        return _enrich(*arguments)


# ---------------------------------------------------------------------- weeks ----
@dataclass(frozen=True)
class Week:
    """One weekly set of reports (at most one file of each kind) and the date of its newest report."""
    start: pd.Timestamp
    files: dict[str, dl.FileInfo]
    repeat: int = 0   # >0 when an earlier set is dated the same day (the same report added twice)

    @property
    def label(self) -> str:
        return f"Reports of {self.start:%d %b %Y}" + (f" ({self.repeat + 1})" if self.repeat else "")


def weeks() -> list[Week]:
    """Every weekly set of readable report files, newest first (tools.history.group_reports).

    Files are dated by their data, and every file is kept: two weekly reports never collapse into one
    set, whatever weekday their scans ended on.
    """
    infos = [info for infos in dl.describe_files(settings.data_dir()).values() for info in infos
             if info.error is None]
    out: list[Week] = []
    days: dict[pd.Timestamp, int] = {}
    for start, files in history.group_reports(infos):
        day = start.normalize()
        out.append(Week(start, files, days.get(day, 0)))
        days[day] = days.get(day, 0) + 1
    return out


def _context_sig() -> tuple:
    """Everything besides the report files that changes how a week is enriched."""
    return (_file_sig(settings.overrides_file()), _file_sig(settings.server_list_file()),
            _file_sig(settings.CONFIG_FILE) + _file_sig(settings.POLICIES_FILE),
            _file_sig(settings.inventory_file()) if settings.inventory_file() else ())


def _read_server_list(errors: dict[str, str] | None = None) -> pd.DataFrame:
    """The team server list, or an empty one if it cannot be used (it only ranks above the Production default,
    so leaving it out never turns a server into development)."""
    try:
        return env.load_server_list(settings.server_list_file())
    except Exception as error:  # noqa: BLE001 - a broken reference file must not take every page down
        if errors is not None:
            errors["server_list"] = (f"Could not use the server list {settings.server_list_file().name}: {error}. "
                                     "Its environments are left out until it is fixed.")
        return pd.DataFrame(columns=env.SERVER_LIST_COLUMNS)


def _resolve(devices: pd.DataFrame, server_list: pd.DataFrame, inventory: pd.DataFrame,
             errors: dict[str, str] | None = None) -> pd.DataFrame:
    """Environment / Env Source per server. If the override file cannot be read, every server is treated as
    production: an override may be what marks a server as production, so ignoring the file is not safe."""
    default = settings.load_policies()["production"]["unknown_environment_is"]
    try:
        overrides = env.load_overrides(settings.overrides_file())
    except Exception as error:  # noqa: BLE001
        if errors is not None:
            errors["overrides"] = (f"Could not read {settings.overrides_file().name}: {error}. Every server is "
                                   "treated as production until the file is fixed.")
        resolved = devices[["Device Name"]].drop_duplicates("Device Name").copy()
        return resolved.assign(Environment=env.PROD, **{"Env Source": env.SRC_ASSUMED})
    return env.resolve_environments(devices, server_list, overrides, default, inventory)


@st.cache_resource(show_spinner=False, max_entries=2)
def _server_list(signature: tuple) -> pd.DataFrame:
    return _read_server_list()


def _with_environment(frame: pd.DataFrame, inventory: pd.DataFrame) -> pd.DataFrame:
    """Add Environment / Env Source with the same rules as the other pages, for any set of servers."""
    if frame.empty:
        return frame.assign(Environment=pd.Series(dtype="object"), **{"Env Source": pd.Series(dtype="object")})
    names = [c for c in ("Device Name", "Applications", "Report Application") if c in frame]
    resolved = _resolve(frame[names], _server_list(_file_sig(settings.server_list_file())),
                        inventory)
    return frame.merge(resolved, on="Device Name", how="left")


# Columns kept for the comparison tables (the reports' long text columns are not needed there).
_COMPARE_COLUMNS = {
    dl.VULN: ["Device Name", "Qualys ID", "Port Number", "Title", "Severity", "Qualys Status", "Applications",
              "Report Application", "Platform", "Operating System", "Ageing in Days", "SLA Status",
              "Date First Found", "Last Scan Date Time"],
    dl.MBSS: ["Device Name", "Qualys Control ID", "Control Description", "Criticality", "Applications",
              "Report Application", "Platform", "OS Family", "Evaluation Date"],
}


def _prepared(kind: str, path: Path, inventory: pd.DataFrame) -> pd.DataFrame:
    frame = _apply_inventory(dl.LOADERS[kind](path), inventory)
    if kind == dl.VULN:
        config = settings.load_config()
        frame = dl.add_sla(frame, config["sla_days"], int(config["sla_due_soon_days"]))
    columns = _COMPARE_COLUMNS.get(kind)
    return frame[[c for c in columns if c in frame.columns]] if columns else frame


def _week_servers(files: tuple[tuple[str, tuple], ...]) -> set[str]:
    """Every server in one week's reports. The CS report lists all of them; the other two add any it misses."""
    servers: set[str] = set()
    for kind, signature in files:
        servers |= set(dl.load_summary(kind, Path(signature[0]))["Device Name"].dropna())
    return servers


@st.cache_resource(show_spinner=False, max_entries=6)
def _changes(kind: str, current: tuple, previous: tuple, current_files: tuple, previous_files: tuple,
             context: tuple, _inventory: pd.DataFrame) -> pd.DataFrame:
    now, before = _prepared(kind, Path(current[0]), _inventory), _prepared(kind, Path(previous[0]), _inventory)
    if kind == dl.CS:
        result = history.cs_changes(now, before)
    else:
        compare = history.vulnerability_changes if kind == dl.VULN else history.mbss_changes
        result = compare(now, before, _week_servers(current_files), _week_servers(previous_files))
    return _with_environment(result.drop(columns=["Environment", "Env Source"], errors="ignore"), _inventory)


def _week_files(week: Week) -> tuple:
    return tuple((kind, _signature(info.path)) for kind, info in sorted(week.files.items()))


def changes(kind: str, current: Week, previous: Week, data: Data) -> pd.DataFrame | None:
    """Per-finding changes of one report kind between two weeks, for every server (filter with scoped()).

    None when either week has no file of that kind. See tools/history.py for the rules.
    """
    if kind not in current.files or kind not in previous.files:
        return None
    with st.spinner("Comparing the two weeks…"):
        return _changes(kind, _signature(current.files[kind].path), _signature(previous.files[kind].path),
                        _week_files(current), _week_files(previous), _context_sig(), data.inventory)


@st.cache_resource(show_spinner=False, max_entries=64)
def _summary(kind: str, signature: tuple, context: tuple, _inventory: pd.DataFrame) -> pd.DataFrame:
    return _with_environment(_apply_inventory(dl.load_summary(kind, Path(signature[0])), _inventory), _inventory)


def trend(week_list: list[Week], data: Data, by: str | tuple[str, ...] = ()) -> pd.DataFrame:
    """Weekly totals in the sidebar scope (per ``by`` group): open findings, past SLA, severities, MBSS, CS."""
    context = _context_sig()
    with st.spinner("Adding up the weekly reports…"):
        parts = [(kind, week.start, _scope(_summary(kind, _signature(info.path), context, data.inventory)))
                 for week in week_list for kind, info in week.files.items()]
    return history.weekly_trend(parts, by)


# -------------------------------------------------------------------- filters ----
ALL = "All"


def sidebar_filters(data: Data) -> None:
    """Global filters. They apply to every page and keep their value when you switch pages."""
    st.session_state["_team_ips"] = data.team_ips
    st.session_state["_inventory_ips"] = data.inventory_ips
    with st.sidebar:
        st.markdown("#### Scope")
        platforms = sorted(data.devices["Platform"].dropna().unique())
        default_platform = settings.load_config()["app"].get("team", "")
        if "f_platform" not in st.session_state:
            st.session_state["f_platform"] = default_platform if default_platform in platforms else ALL
        st.selectbox("Platform", [ALL] + platforms, key="f_platform")
        st.segmented_control("Environment", [ALL, env.PROD, env.DEV], key="f_env", default=ALL)
        if data.team_ips:
            st.toggle("Only servers in my team's server list", key="f_team",
                      help=f"Limits every page to the {len(data.team_ips)} servers in {settings.server_list_file().name}.")
        if data.inventory_ips:
            st.toggle("Only AI platform servers (inventory)", key="f_inventory",
                      help=f"Limits every page to the {len(data.inventory_ips)} servers in the AI Platforms Inventory.")
        scoped = _scope(data.devices, applications=False)
        options = sorted(scoped["Applications"].dropna().unique())
        # Drop selections that left the scope (for example after switching platform).
        st.session_state["f_apps"] = [app for app in st.session_state.get("f_apps", []) if app in options]
        st.multiselect("Applications", options, key="f_apps", placeholder="All applications")
        st.caption(f"{scoped['Device Name'].nunique():,} servers in scope before the application filter.")


def _scope(frame: pd.DataFrame, applications: bool = True) -> pd.DataFrame:
    if frame.empty:
        return frame
    state = st.session_state
    mask = pd.Series(True, index=frame.index)
    if state.get("f_platform", ALL) != ALL:
        mask &= frame["Platform"] == state["f_platform"]
    if state.get("f_env") in (env.PROD, env.DEV):
        mask &= frame["Environment"] == state["f_env"]
    if state.get("f_team") and "Device Name" in frame:
        mask &= frame["Device Name"].isin(st.session_state["_team_ips"])
    if state.get("f_inventory") and "Device Name" in frame:
        mask &= frame["Device Name"].isin(st.session_state["_inventory_ips"])
    if applications and state.get("f_apps"):
        mask &= frame["Applications"].isin(state["f_apps"])
    return frame[mask]


def scoped(frame: pd.DataFrame) -> pd.DataFrame:
    """Apply the sidebar filters to any frame with Device Name, Applications, Platform and Environment."""
    return _scope(frame)


def filtered(data: Data) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """(vulnerabilities, mbss, cs controls, devices) after the sidebar filters."""
    st.session_state["_team_ips"] = data.team_ips
    st.session_state["_inventory_ips"] = data.inventory_ips
    return _scope(data.vulns), _scope(data.mbss), _scope(data.cs), _scope(data.devices)


def scope_label() -> str:
    state = st.session_state
    parts = [state.get("f_platform", ALL) if state.get("f_platform", ALL) != ALL else "All platforms"]
    if state.get("f_env") in (env.PROD, env.DEV):
        parts.append(state["f_env"])
    if state.get("f_team"):
        parts.append("team servers")
    if state.get("f_inventory"):
        parts.append("AI inventory servers")
    if state.get("f_apps"):
        apps = state["f_apps"]
        parts.append(apps[0] if len(apps) == 1 else f"{len(apps)} applications")
    return " · ".join(parts)


def as_of(frame: pd.DataFrame, column: str) -> str:
    if frame.empty or column not in frame:
        return "no data"
    latest = pd.to_datetime(frame[column], errors="coerce").max()
    return "unknown" if pd.isna(latest) else f"{latest:%d %b %Y}"
