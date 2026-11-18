"""MBSS: failed Minimum Baseline Security Standard controls from the compliance scan."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from guardrails.input_checks import strip_html
from ui import charts, components, state, theme
from workflows import recommend

ROW_COLUMNS = ["Platform", "Applications", "Server Role", "Device Name", "Environment", "Criticality", "OS Family",
               "Control Description", "Qualys Control ID", "Days Failing", "MBSS Score", "Evaluation Date", "Report Application"]


def _page_filters(frame: pd.DataFrame) -> pd.DataFrame:
    with st.container(border=True):
        one, two, three = st.columns([3, 2, 2.5])
        levels = one.pills("Criticality", [s for s in charts.SEVERITY_ORDER if s in set(frame["Criticality"])],
                           selection_mode="multi", key="m_criticality")
        family = two.pills("Baseline", sorted(frame["OS Family"].dropna().unique()), key="m_os")
        search = three.text_input("Search control", key="m_search", placeholder="e.g. sshd, audit, password")
    mask = pd.Series(True, index=frame.index)
    if levels:
        mask &= frame["Criticality"].isin(levels)
    if family:
        mask &= frame["OS Family"] == family
    if search:
        mask &= frame["Control Description"].str.contains(search, case=False, regex=False, na=False)
    return frame[mask]


def _grouped(frame: pd.DataFrame) -> pd.DataFrame:
    grouped = frame.groupby(["Qualys Control ID", "Control Description"], sort=False, dropna=False).agg(
        Criticality=("Criticality", "first"),
        Baseline=("OS Family", "first"),
        Servers=("Device Name", "nunique"),
        Applications=("Applications", "nunique"),
        **{"Median days failing": ("Days Failing", "median")},
    ).reset_index().rename(columns={"Control Description": "Control", "Qualys Control ID": "Control ID"})
    rank = {name: index for index, name in enumerate(charts.SEVERITY_ORDER)}
    grouped["_rank"] = grouped["Criticality"].map(rank).fillna(9)
    grouped = grouped.sort_values(["_rank", "Servers"], ascending=[True, False]).drop(columns="_rank")
    return grouped[["Control", "Criticality", "Baseline", "Servers", "Applications", "Median days failing", "Control ID"]]


def _detail(frame: pd.DataFrame, control_id: str, control: str) -> None:
    rows = frame[(frame["Qualys Control ID"] == control_id) & (frame["Control Description"] == control)]
    first = rows.sort_values("Days Failing", ascending=False).iloc[0]
    with st.container(border=True):
        theme.title("Selected control")
        st.markdown(f"#### {control}")
        theme.badges([(str(first["Criticality"]), "solid"), (f"{first['OS Family']} baseline", ""),
                      (f"{rows['Device Name'].nunique():,} servers", "gray"),
                      (f"Qualys control {control_id}", "gray")])
        left, right = st.columns([1, 1])
        with left:
            with st.expander("Why it matters", expanded=True):
                st.write(strip_html(first.get("RATIONALE")) or "Not provided.")
            with st.expander("Baseline remediation text"):
                st.write(strip_html(first.get("Remediation")) or "Not provided.")
            with st.expander("Expected configuration and current evidence"):
                st.code(strip_html(first.get("Expected Configuration"))[:3000] or "Not provided.", language=None)
                st.code(strip_html(first.get("Posture Evidence"))[:3000] or "Not provided.", language=None)
        with right:
            servers = rows[["Device Name", "Applications", "Environment", "Days Failing", "MBSS Score"]]
            st.dataframe(servers.sort_values("Days Failing", ascending=False), hide_index=True, height=330)
    components.recommendation_panel(recommend.MBSS, first.to_dict(), key=f"{control_id}-{control[:60]}")


def _tab_controls(frame: pd.DataFrame) -> None:
    grouped = _grouped(frame)
    st.caption("Select a control to see the affected servers and ask for a fix.")
    event = st.dataframe(grouped, hide_index=True, on_select="rerun", selection_mode="single-row", key="m_grouped",
                         height=380, column_config={"Control": st.column_config.TextColumn(width="large"),
                                                    "Median days failing": st.column_config.NumberColumn(format="%d")})
    picked = components.selected_row(event)
    if picked is not None and picked < len(grouped):
        row = grouped.iloc[picked]
        _detail(frame, row["Control ID"], row["Control"])


def _tab_servers(frame: pd.DataFrame) -> None:
    flags = frame.assign(_critical=frame["Criticality"].eq("Critical"), _high=frame["Criticality"].eq("High"))
    servers = flags.groupby(["Device Name", "Applications", "Platform", "Environment", "OS Family"], dropna=False).agg(
        **{"Failed checks": ("Control Description", "size"), "Critical": ("_critical", "sum"), "High": ("_high", "sum"),
           "Longest failing (days)": ("Days Failing", "max")}).reset_index()
    components.capped_table(servers.sort_values("Critical", ascending=False), "m_servers", "mbss_by_server.csv",
                            height=420)


def _tab_rows(frame: pd.DataFrame) -> None:
    columns = [c for c in ROW_COLUMNS if c in frame.columns]
    components.capped_table(frame[columns], "m_rows", "mbss_failed_checks.csv", height=420)


def render() -> None:
    data = state.load()
    _, mbss, _, _ = state.filtered(data)
    theme.hero(
        "MBSS · Qualys policy compliance",
        "Failed baseline controls",
        "Minimum Baseline Security Standard checks that currently fail, per server. Controls are grouped so one "
        "hardening change can be planned once and rolled out to every affected server.",
        [("Report:", data.files["mbss"].name if data.files["mbss"] else "not loaded"),
         ("Evaluated:", state.as_of(data.mbss, "Evaluation Date")), ("Scope:", state.scope_label())],
    )
    if "mbss" in data.errors:
        st.error(data.errors["mbss"])
        return
    if mbss.empty:
        st.info("No failed MBSS checks in this scope. Check the sidebar filters or add the report on the Settings page.")
        return
    frame = _page_filters(mbss)
    if frame.empty:
        st.info("No controls match these filters.")
        return

    critical = int((frame["Criticality"] == "Critical").sum())
    servers = frame["Device Name"].nunique()
    theme.kpis([
        {"label": "Failed checks", "value": theme.number(len(frame)), "tone": "primary",
         "sub": f"{frame['Qualys Control ID'].nunique():,} unique controls", "progress": critical / len(frame)},
        {"label": "Critical", "value": theme.number(critical), "tone": "alert",
         "sub": f"{theme.percent(critical, len(frame))} of failed checks"},
        {"label": "High", "value": theme.number((frame["Criticality"] == "High").sum()), "sub": "failed checks"},
        {"label": "Servers affected", "value": theme.number(servers),
         "sub": f"{len(frame) / servers:.0f} failed checks per server on average"},
        {"label": "Applications", "value": theme.number(frame["Applications"].nunique()), "sub": "with failed checks"},
        {"label": "Median days failing", "value": theme.number(frame["Days Failing"].median()),
         "sub": "since the posture last changed"},
    ])

    one, two = st.columns([1, 1.6])
    with one, st.container(border=True):
        theme.title("Failed checks by criticality")
        counts = frame["Criticality"].value_counts().rename_axis("Criticality").reset_index(name="Failed checks")
        charts.show(charts.ordinal_bars(counts, "Criticality", "Failed checks", charts.SEVERITY_ORDER,
                                        charts.SEVERITY_COLORS, "Failed checks"))
    with two, st.container(border=True):
        theme.title("Controls failing on most servers", "Top 8")
        top = (frame.groupby("Control Description")["Device Name"].nunique().nlargest(8)
               .rename_axis("Control").reset_index(name="Servers"))
        top["Control"] = top["Control"].str.slice(0, 70) + top["Control"].str.len().gt(70).map({True: "…", False: ""})
        charts.show(charts.ranked_bars(top, "Control", "Servers", "Servers failing the control"))

    tabs = st.tabs(["Controls (grouped)", "By server", "All rows"], key="m_tabs", on_change="rerun")
    for tab, body in zip(tabs, (_tab_controls, _tab_servers, _tab_rows)):
        if tab.open:
            with tab:
                body(frame)
