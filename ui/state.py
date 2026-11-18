"""Shared data for every page: load the reports once, enrich them, apply the sidebar filters."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import streamlit as st

import settings
from memory.knowledge_base import KnowledgeBase
from tools import classifier, data_loader as dl, environment as env


@dataclass
class Data:
    vulns: pd.DataFrame
    mbss: pd.DataFrame
    cs: pd.DataFrame
    devices: pd.DataFrame                     # one row per server: environment, source, platform
    files: dict[str, Path | None]
    errors: dict[str, str] = field(default_factory=dict)
    team_ips: frozenset[str] = frozenset()


def _signature(path: Path | None) -> tuple:
    if path is None or not path.exists():
        return ("missing",)
    stat = path.stat()
    return (str(path), stat.st_size, stat.st_mtime_ns)


@st.cache_resource(show_spinner=False, max_entries=6)
def _read(kind: str, signature: tuple) -> pd.DataFrame:
    return dl.LOADERS[kind](Path(signature[0]))


@st.cache_resource(show_spinner=False, max_entries=2)
def _enrich(signatures: tuple, overrides_sig: tuple, server_sig: tuple, config_sig: tuple, labels_sig: int) -> Data:
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

    server_list = env.load_server_list(settings.server_list_file())
    overrides = env.load_overrides(settings.overrides_file())
    known = [f[["Device Name", "Applications", "Platform"]] for f in frames.values() if not f.empty]
    all_devices = (pd.concat(known).drop_duplicates("Device Name") if known
                   else pd.DataFrame(columns=["Device Name", "Applications", "Platform"]))
    resolved = env.resolve_environments(all_devices, server_list, overrides,
                                        policies["production"]["unknown_environment_is"])
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
                team_ips)


def _file_sig(path: Path) -> tuple:
    return (path.stat().st_mtime_ns,) if path.exists() else (0,)


def load() -> Data:
    """Return the enriched data, reading the Excel files only when something changed."""
    found = dl.discover_files(settings.data_dir())
    chosen = []
    for kind in (dl.VULN, dl.MBSS, dl.CS):
        picked = st.session_state.get(f"file::{kind}")
        options = found[kind]
        path = next((p for p in options if p.name == picked), options[0] if options else None)
        chosen.append(_signature(path))
    arguments = (tuple(chosen), _file_sig(settings.overrides_file()), _file_sig(settings.server_list_file()),
                 _file_sig(settings.CONFIG_FILE) + _file_sig(settings.POLICIES_FILE), len(KnowledgeBase().topic_labels()))
    with st.spinner("Reading the reports. The first read of a new file takes about half a minute."):
        return _enrich(*arguments)


# -------------------------------------------------------------------- filters ----
ALL = "All"


def sidebar_filters(data: Data) -> None:
    """Global filters. They apply to every page and keep their value when you switch pages."""
    st.session_state["_team_ips"] = data.team_ips
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
    if applications and state.get("f_apps"):
        mask &= frame["Applications"].isin(state["f_apps"])
    return frame[mask]


def filtered(data: Data) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """(vulnerabilities, mbss, cs controls, devices) after the sidebar filters."""
    st.session_state["_team_ips"] = data.team_ips
    return _scope(data.vulns), _scope(data.mbss), _scope(data.cs), _scope(data.devices)


def scope_label() -> str:
    state = st.session_state
    parts = [state.get("f_platform", ALL) if state.get("f_platform", ALL) != ALL else "All platforms"]
    if state.get("f_env") in (env.PROD, env.DEV):
        parts.append(state["f_env"])
    if state.get("f_team"):
        parts.append("team servers")
    if state.get("f_apps"):
        apps = state["f_apps"]
        parts.append(apps[0] if len(apps) == 1 else f"{len(apps)} applications")
    return " · ".join(parts)


def as_of(frame: pd.DataFrame, column: str) -> str:
    if frame.empty or column not in frame:
        return "no data"
    latest = pd.to_datetime(frame[column], errors="coerce").max()
    return "unknown" if pd.isna(latest) else f"{latest:%d %b %Y}"
