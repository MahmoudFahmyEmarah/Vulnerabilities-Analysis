"""Overview: the three checks side by side, and where to look first."""
from __future__ import annotations

import pandas as pd
import streamlit as st

import settings
from tools import environment as env
from ui import charts, components, state, theme


def _by_application(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame) -> pd.DataFrame:
    table = devices.groupby("Applications").agg(
        Servers=("Device Name", "nunique"),
        Production=("Environment", lambda s: int((s == env.PROD).sum())),
        Development=("Environment", lambda s: int((s == env.DEV).sum())),
    )
    if not vulns.empty:
        grouped = vulns.groupby("Applications")
        table["Open vulnerabilities"] = grouped.size()
        table["Past SLA"] = grouped["SLA Status"].apply(lambda s: int((s == "Breached").sum()))
        table["High or critical"] = grouped["Severity"].apply(lambda s: int(s.isin(["High", "Critical"]).sum()))
    if not mbss.empty:
        table["MBSS failed"] = mbss.groupby("Applications").size()
    if not cs.empty:
        table["CS control gaps"] = cs.groupby("Applications")["Gaps"].sum()
    table = table.fillna(0).astype(int).reset_index()
    sort_by = [c for c in ("Past SLA", "MBSS failed", "CS control gaps") if c in table]
    return table.sort_values(sort_by, ascending=False) if sort_by else table


def _inventory_check(data: state.Data) -> None:
    """Compare the AI Platforms Inventory (the reference) with what the three reports contain."""
    inventory = data.inventory
    if inventory.empty:
        return
    reports = {"Vulnerability report": data.vulns, "MBSS report": data.mbss, "CS Controls report": data.cs}
    table = inventory[["IP", "Hostname", "AI Platform", "Server Role", "Environment"]].copy()
    table["Environment"] = table["Environment"].fillna("Not stated")
    for label, frame in reports.items():
        present = set(frame["Device Name"]) if not frame.empty else set()
        table[label] = table["IP"].isin(present).map({True: "Yes", False: "No"})
    in_any = table[list(reports)].eq("Yes").any(axis=1)
    table.insert(5, "In any report", in_any.map({True: "Yes", False: "No"}))
    devices = data.devices.set_index("Device Name")
    if "Report Application" in devices:
        table["Name in the reports"] = table["IP"].map(devices["Report Application"])
        renamed = (table["Name in the reports"].notna()
                   & (table["Name in the reports"].str.casefold() != table["AI Platform"].str.casefold()))
    else:
        renamed = pd.Series(False, index=table.index)
    set_by_inventory = int((data.devices["Env Source"] == env.SRC_INVENTORY).sum())

    with st.container(border=True):
        theme.title("AI Platforms Inventory check",
                    "The inventory is the reference for AI platform servers: its platform names and environments are "
                    "used in every page. This compares it with the three reports (all platforms, sidebar filters not applied).")
        theme.kpis([
            {"label": "Servers in the inventory", "value": theme.number(len(table)), "tone": "primary",
             "sub": f"{table['AI Platform'].nunique()} AI platforms"},
            {"label": "In no report", "value": theme.number((~in_any).sum()), "tone": "alert" if (~in_any).any() else "",
             "sub": "not scanned, or scanned under another address"},
            {"label": "Missing from the vulnerability report",
             "value": theme.number((table["Vulnerability report"] == "No").sum()), "sub": "no open findings or not scanned"},
            {"label": "Named differently in the reports", "value": theme.number(renamed.sum()),
             "sub": "the inventory name is shown instead"},
            {"label": "Environment set by the inventory", "value": theme.number(set_by_inventory),
             "sub": "servers in the reports"},
        ])
        only_missing = st.toggle("Only servers that are in no report", key="o_inventory_missing")
        shown = table[~in_any] if only_missing else table
        components.capped_table(shown.sort_values(["In any report", "AI Platform", "IP"]), "overview-inventory",
                                "ai_inventory_check.csv", height=320)


def render() -> None:
    data = state.load()
    vulns, mbss, cs, devices = state.filtered(data)
    config = settings.load_config()

    theme.hero(
        "Security posture · " + config["app"].get("team", ""),
        "Vulnerabilities, MBSS and CS Controls in one view",
        "Open scanner findings, failed baseline (MBSS) controls and cybersecurity control coverage for the servers "
        "in scope. Use the sidebar to narrow the scope; every page follows it.",
        [("Vulnerabilities as of", state.as_of(data.vulns, "Last Scan Date Time")),
         ("MBSS as of", state.as_of(data.mbss, "Evaluation Date")),
         ("Scope:", state.scope_label())],
    )
    for message in data.errors.values():
        st.error(message)
    if devices.empty:
        st.info("No report files were found for this scope. Add the Excel reports on the Settings page.")
        return

    breached = int((vulns["SLA Status"] == "Breached").sum()) if not vulns.empty else 0
    due_soon = int((vulns["SLA Status"] == "Due soon").sum()) if not vulns.empty else 0
    servers_with_gap = int((cs["Gaps"] > 0).sum()) if not cs.empty else 0
    production = int((devices["Environment"] == env.PROD).sum())
    theme.kpis([
        {"label": "Open vulnerabilities", "value": theme.number(len(vulns)), "tone": "primary",
         "sub": f"{vulns['Title'].nunique():,} unique findings" if not vulns.empty else "no report loaded",
         "progress": breached / len(vulns) if len(vulns) else None},
        {"label": "Past SLA", "value": theme.number(breached), "tone": "alert",
         "sub": f"{theme.percent(breached, len(vulns))} of open findings"},
        {"label": f"Due in ≤{config['sla_due_soon_days']} days", "value": theme.number(due_soon),
         "sub": "still inside SLA"},
        {"label": "MBSS failed checks", "value": theme.number(len(mbss)),
         "sub": f"{int((mbss['Criticality'] == 'Critical').sum()):,} critical" if not mbss.empty else "no report loaded"},
        {"label": "Servers with a CS gap", "value": theme.number(servers_with_gap),
         "sub": f"of {len(cs):,} servers in the CS report" if not cs.empty else "no report loaded"},
        {"label": "Servers in scope", "value": theme.number(devices["Device Name"].nunique()),
         "sub": f"{production:,} production · {len(devices) - production:,} development"},
    ])

    unconfirmed = int((devices["Env Source"] == env.SRC_ASSUMED).sum())
    if unconfirmed:
        theme.note(f"{unconfirmed:,} of {len(devices):,} servers have no confirmed environment and are treated as "
                   "production. Map them on the Settings page to unlock daytime windows for development servers.")

    left, right = st.columns(2)
    with left, st.container(border=True):
        theme.title("Open vulnerabilities by severity", "Colour shows SLA status")
        if vulns.empty:
            st.caption("No vulnerability data in scope.")
        else:
            counts = vulns.groupby(["Severity", "SLA Status"]).size().reset_index(name="Findings")
            charts.show(charts.stacked_bars(counts, "Severity", "Findings", "SLA Status", charts.SEVERITY_ORDER,
                                            charts.SLA_ORDER, charts.SLA_COLORS, "Open findings"))
    with right, st.container(border=True):
        theme.title("Applications with most findings past SLA", "Top 10")
        if breached:
            top = (vulns[vulns["SLA Status"] == "Breached"].groupby("Applications").size()
                   .nlargest(10).reset_index(name="Past SLA"))
            charts.show(charts.ranked_bars(top, "Applications", "Past SLA", "Findings past SLA", color=charts.RED))
        else:
            st.caption("Nothing is past SLA in this scope.")

    with st.container(border=True):
        theme.title("By application", "Sorted by findings past SLA. Click a column header to re-sort.")
        table = _by_application(vulns, mbss, cs, devices)
        column_config = {}
        if "Past SLA" in table and table["Past SLA"].max() > 0:
            column_config["Past SLA"] = st.column_config.ProgressColumn(
                "Past SLA", format="%d", min_value=0, max_value=int(table["Past SLA"].max()))
        components.capped_table(table, "overview-apps", "applications_overview.csv", column_config=column_config)

    _inventory_check(data)
