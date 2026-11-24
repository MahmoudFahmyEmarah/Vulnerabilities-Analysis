"""Overview: the three checks side by side, and where to look first."""
from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

import settings
from tools import data_loader as dl, environment as env, history
from ui import charts, components, state, theme
from workflows import export


def _by_application(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame) -> pd.DataFrame:
    """The short per-application table; the counts come from the Excel export's application summary."""
    summary = export.application_summary(vulns, mbss, cs, devices)
    table = summary[["Application", "Servers", "Production", "Development"]].rename(
        columns={"Application": "Applications"})
    if not vulns.empty:
        table["Open vulnerabilities"] = summary["Open findings"]
        table["Past SLA"] = summary["Past SLA"]
        table["High or critical"] = summary["Critical"] + summary["High"]
    if not mbss.empty:
        table["MBSS failed"] = summary["MBSS failed checks"]
    if not cs.empty:
        table["CS control gaps"] = summary[[f"{control} gaps" for control in dl.CS_CONTROLS]].sum(axis=1)
    sort_by = [c for c in ("Past SLA", "MBSS failed", "CS control gaps") if c in table]
    return table.sort_values(sort_by, ascending=False, kind="stable") if sort_by else table


def _vulnerability_changes(data: state.Data) -> pd.DataFrame | None:
    """New / Fixed per application: the loaded vulnerability report against the week before it.

    None when there is no earlier week, or the loaded file is not the newest of its week.
    """
    loaded = data.files.get(dl.VULN)
    if loaded is None:
        return None
    weeks = state.weeks()
    index = next((i for i, week in enumerate(weeks) if dl.VULN in week.files
                  and week.files[dl.VULN].path.resolve() == loaded.resolve()), None)
    if index is None:
        return None
    previous = next((week for week in weeks[index + 1:] if dl.VULN in week.files), None)
    if previous is None:
        return None
    changes = state.changes(dl.VULN, weeks[index], previous, data)
    return None if changes is None else history.count_changes(state.scoped(changes))


def _cs_date(cs_file) -> str:
    if not cs_file or not cs_file.exists():
        return "no file"
    info = dl.file_info(dl.CS, cs_file)
    how = "week set on the Settings page" if info.date_source == dl.USER_DATE else "workbook saved"
    return f"{info.report_date:%d %b %Y} ({how})"


def _export_button(data: state.Data, vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame,
                   devices: pd.DataFrame, config: dict) -> None:
    """Everything in the sidebar scope as one Excel workbook, built only when the button is clicked."""
    cs_file = data.files.get(dl.CS)
    timezone = settings.load_policies()["calendar"]["timezone"]
    # Worked out now: the build runs on another thread, where session state is not available.
    options = {
        "scope": state.scope_label(),
        "report_dates": {
            "Vulnerability report as of": state.as_of(data.vulns, "Last Scan Date Time"),
            "MBSS report as of": state.as_of(data.mbss, "Evaluation Date"),
            # Same date as the Settings and Trends pages: when the workbook was saved (not when it was
            # copied), or the week set for it on the Settings page.
            "CS Controls report dated": _cs_date(cs_file),
        },
        "timezone": timezone,
        "due_soon_days": int(config["sla_due_soon_days"]),
        "staff_columns": settings.load_policies()["llm_input"].get("never_send", export.STAFF_COLUMNS),
        "changes": _vulnerability_changes(data),   # week-over-week New / Fixed columns
    }
    applications = devices["Applications"].nunique()
    left, right = st.columns([2, 1], vertical_alignment="center")
    left.caption(f"Export to Excel: a summary with charts, one row for each of the {applications:,} applications in "
                 f"scope, and every open finding ({len(vulns):,}), failed MBSS check ({len(mbss):,}) and CS gap. "
                 "Building the full workbook takes a few seconds.")
    right.download_button(
        "Export to Excel", lambda: export.build_workbook(vulns, mbss, cs, devices, **options),
        file_name=f"security_posture_{datetime.now(ZoneInfo(timezone)):%Y-%m-%d}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key="overview-export", icon=":material/download:", type="primary", width="stretch")


def _donuts(vulns: pd.DataFrame, devices: pd.DataFrame) -> None:
    """How the open findings and the servers in scope split, at a glance."""
    def ring(column, title: str, caption: str, frame: pd.DataFrame, by: str, order: list[str], colors: list[str],
             centre: str, value_title: str, labels: dict[str, str] | None = None) -> None:
        with column, st.container(border=True):
            theme.title(title, caption)
            if frame.empty or by not in frame:
                st.caption("No data in scope.")
                return
            counts = frame[by].value_counts().rename_axis(by).reset_index(name="Count")
            charts.show(charts.donut(counts, by, "Count", order, colors, centre, value_title, labels))

    one, two, three, four = st.columns(4)
    ring(one, "By severity", "Open vulnerabilities", vulns, "Severity", charts.SEVERITY_ORDER,
         charts.SEVERITY_COLORS, "open findings", "Open findings")
    ring(two, "By SLA status", "Open vulnerabilities", vulns, "SLA Status", charts.SLA_ORDER, charts.SLA_COLORS,
         "open findings", "Open findings")
    ring(three, "By owner", "Who fixes the open vulnerabilities", vulns, "Topic", charts.OWNER_ORDER,
         charts.OWNER_COLORS, "open findings", "Open findings", charts.OWNER_LABELS)
    ring(four, "By environment", "Servers in scope", devices.drop_duplicates("Device Name"), "Environment",
         charts.ENV_ORDER, charts.ENV_COLORS, "servers", "Servers")


def _more_bars(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame) -> None:
    """Where the open work sits: applications, environments, MBSS criticality and CS controls."""
    left, right = st.columns([1.5, 1])
    with left, st.container(border=True):
        theme.title("Applications with most open vulnerabilities", "Top 10, by severity")
        if vulns.empty:
            st.caption("No vulnerability data in scope.")
        else:
            top = list(vulns.groupby("Applications").size().nlargest(10).index)
            counts = (vulns[vulns["Applications"].isin(top)].groupby(["Applications", "Severity"]).size()
                      .reset_index(name="Findings"))
            charts.show(charts.stacked_bars(counts, "Applications", "Findings", "Severity", top, charts.SEVERITY_ORDER,
                                            charts.SEVERITY_COLORS, "Open findings"))
    with right:
        with st.container(border=True):
            theme.title("Open vulnerabilities by environment", "Colour shows SLA status")
            if vulns.empty:
                st.caption("No vulnerability data in scope.")
            else:
                counts = vulns.groupby(["Environment", "SLA Status"]).size().reset_index(name="Findings")
                charts.show(charts.stacked_bars(counts, "Environment", "Findings", "SLA Status", charts.ENV_ORDER,
                                                charts.SLA_ORDER, charts.SLA_COLORS, "Open findings", headroom=0.3))
        with st.container(border=True):
            theme.title("MBSS failed checks by criticality")
            if mbss.empty:
                st.caption("No MBSS data in scope.")
            else:
                counts = mbss["Criticality"].value_counts().rename_axis("Criticality").reset_index(name="Failed checks")
                charts.show(charts.ordinal_bars(counts, "Criticality", "Failed checks", charts.SEVERITY_ORDER,
                                                charts.SEVERITY_COLORS, "Failed checks", headroom=0.3))

    left, right = st.columns(2)
    with left, st.container(border=True):
        theme.title("Open vulnerabilities by operating system", "Top 8")
        if vulns.empty or "OS Family" not in vulns:
            st.caption("No vulnerability data in scope.")
        else:
            top = vulns["OS Family"].value_counts().nlargest(8).rename_axis("Operating system").reset_index(name="Findings")
            charts.show(charts.ranked_bars(top, "Operating system", "Findings", "Open findings"))
    with right, st.container(border=True):
        theme.title("CS control gaps", "Servers missing each control, fully or in part")
        long = dl.cs_long(cs) if not cs.empty else pd.DataFrame()
        gaps = long[long["State"].isin(["Gap", "Partial"])] if not long.empty else long
        if gaps.empty:
            st.caption("No CS control gaps in scope." if not cs.empty else "No CS Controls data in scope.")
        else:
            counts = gaps.groupby(["Control", "State"]).size().reset_index(name="Servers")
            charts.show(charts.stacked_bars(counts, "Control", "Servers", "State", list(dl.CS_CONTROLS),
                                            charts.CS_ORDER, charts.CS_COLORS, "Servers", headroom=0.25))


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
    _export_button(data, vulns, mbss, cs, devices, config)

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

    _donuts(vulns, devices)

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

    _more_bars(vulns, mbss, cs)

    with st.container(border=True):
        theme.title("By application", "Sorted by findings past SLA. Click a column header to re-sort.")
        table = _by_application(vulns, mbss, cs, devices)
        column_config = {}
        if "Past SLA" in table and table["Past SLA"].max() > 0:
            column_config["Past SLA"] = st.column_config.ProgressColumn(
                "Past SLA", format="%d", min_value=0, max_value=int(table["Past SLA"].max()))
        components.capped_table(table, "overview-apps", "applications_overview.csv", column_config=column_config)

    _inventory_check(data)
