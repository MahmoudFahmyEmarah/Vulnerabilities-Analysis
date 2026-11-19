"""Vulnerabilities: open scanner findings, SLA pressure, OS vs application split, AI fix."""
from __future__ import annotations

import pandas as pd
import streamlit as st

import settings
from guardrails.input_checks import strip_html
from tools import classifier
from ui import charts, components, state, theme
from workflows import recommend

AGE_BUCKETS = [(-1, 7, "0–7"), (7, 14, "8–14"), (14, 30, "15–30"), (30, 45, "31–45"), (45, 90, "46–90"),
               (90, 180, "91–180"), (180, 365, "181–365"), (365, 10**6, "Over 365")]
ROW_COLUMNS = ["Applications", "Server Role", "Device Name", "Environment", "Title", "Severity", "Topic", "SLA Status",
               "Ageing in Days", "SLA Remaining Days", "Operating System", "Qualys Status", "Date First Found",
               "Related CVEs", "Report Application"]


def _page_filters(frame: pd.DataFrame) -> pd.DataFrame:
    with st.container(border=True):
        one, two, three, four = st.columns([3, 2.6, 2.4, 2.2])
        severities = one.pills("Severity", [s for s in charts.SEVERITY_ORDER if s in set(frame["Severity"])],
                               selection_mode="multi", key="v_severity")
        statuses = two.pills("SLA status", charts.SLA_ORDER, selection_mode="multi", key="v_sla")
        topic = three.pills("Owner", [classifier.OS, classifier.APP], key="v_topic")
        search = four.text_input("Search title or CVE", key="v_search", placeholder="e.g. log4j, kernel, CVE-2026")
    mask = pd.Series(True, index=frame.index)
    if severities:
        mask &= frame["Severity"].isin(severities)
    if statuses:
        mask &= frame["SLA Status"].isin(statuses)
    if topic:
        mask &= frame["Topic"] == topic
    if search:
        hit = frame["Title"].str.contains(search, case=False, regex=False, na=False)
        if "Related CVEs" in frame:
            hit |= frame["Related CVEs"].astype("string").str.contains(search, case=False, regex=False, na=False)
        mask &= hit
    return frame[mask]


def _grouped(frame: pd.DataFrame) -> pd.DataFrame:
    rank = {name: index for index, name in enumerate(charts.SEVERITY_ORDER)}
    flagged = frame.assign(_breached=frame["SLA Status"].eq("Breached"), _rank=frame["Severity"].map(rank).fillna(9))
    grouped = flagged.groupby("Title", sort=False).agg(
        _rank=("_rank", "min"),   # the same title can carry different severities per server: show the worst
        Owner=("Topic", "first"),
        Servers=("Device Name", "nunique"),
        Applications=("Applications", "nunique"),
        **{"Past SLA": ("_breached", "sum"),
           "Oldest (days)": ("Ageing in Days", "max"),
           "OS": ("OS Family", lambda s: ", ".join(sorted(set(s))[:3]))},
    ).reset_index().rename(columns={"Title": "Finding"})
    grouped.insert(1, "Severity", grouped["_rank"].map(dict(enumerate(charts.SEVERITY_ORDER))).fillna("Unknown"))
    return grouped.sort_values(["_rank", "Past SLA", "Servers"], ascending=[True, False, False]).drop(columns="_rank")


def _detail(frame: pd.DataFrame, title: str) -> None:
    rows = frame[frame["Title"] == title]
    first = rows.sort_values("Ageing in Days", ascending=False).iloc[0]
    with st.container(border=True):
        theme.title("Selected finding")
        st.markdown(f"#### {title}")
        worst = next((level for level in charts.SEVERITY_ORDER if level in set(rows["Severity"])), str(first["Severity"]))
        theme.badges([(worst, "solid"), (str(first["Topic"]), ""),
                      (f"{rows['Device Name'].nunique():,} servers", "gray"),
                      (f"{int((rows['SLA Status'] == 'Breached').sum()):,} past SLA", "red"),
                      (f"Classified by: {first['Topic Rule']}", "gray")])
        left, right = st.columns([1, 1])
        with left:
            theme.facts([("Applications", ", ".join(sorted(rows["Applications"].unique())[:8])),
                         ("Operating systems", ", ".join(sorted(rows["OS Family"].unique()))),
                         ("CVEs", strip_html(first.get("Related CVEs")).replace("\n", ", ")[:400]),
                         ("First found", f"{rows['Date First Found'].min():%d %b %Y}" if rows["Date First Found"].notna().any() else ""),
                         ("Oldest", f"{int(rows['Ageing in Days'].max())} days")])
            with st.expander("Scanner description"):
                st.write(strip_html(first.get("Description")) or "Not provided.")
            with st.expander("Scanner solution"):
                st.write(strip_html(first.get("Solution")) or "Not provided.")
            with st.expander("Scan result on the oldest server"):
                st.code(strip_html(first.get("Results"))[:4000] or "Not provided.", language=None)
        with right:
            columns = [c for c in ("Device Name", "Applications", "Server Role", "Environment", "Operating System",
                                   "Ageing in Days", "SLA Remaining Days", "SLA Status") if c in rows.columns]
            servers = rows[columns].sort_values("Ageing in Days", ascending=False)
            st.dataframe(servers, hide_index=True, height=330)
    components.recommendation_panel(recommend.VULNERABILITY, first.to_dict(), key=title)


def render() -> None:
    data = state.load()
    vulns, _, _, _ = state.filtered(data)
    config = settings.load_config()
    theme.hero(
        "Vulnerabilities · Qualys report",
        "Open vulnerabilities",
        "Every open finding per server. Findings are grouped by title so one fix can be planned once and applied "
        "to all affected servers. Owner shows who fixes it: the operating system team or the application team.",
        [("Report:", data.files["vulnerabilities"].name if data.files["vulnerabilities"] else "not loaded"),
         ("Last scan:", state.as_of(data.vulns, "Last Scan Date Time")), ("Scope:", state.scope_label())],
    )
    if "vulnerabilities" in data.errors:
        st.error(data.errors["vulnerabilities"])
        return
    if vulns.empty:
        st.info("No open vulnerabilities in this scope. Check the sidebar filters or add the report on the Settings page.")
        return

    frame = _page_filters(vulns)
    if frame.empty:
        st.info("No findings match these filters.")
        return
    breached = int((frame["SLA Status"] == "Breached").sum())
    os_count = int((frame["Topic"] == classifier.OS).sum())
    theme.kpis([
        {"label": "Open findings", "value": theme.number(len(frame)), "tone": "primary",
         "sub": f"{frame['Title'].nunique():,} unique", "progress": breached / len(frame)},
        {"label": "Past SLA", "value": theme.number(breached), "tone": "alert",
         "sub": f"{theme.percent(breached, len(frame))} of findings"},
        {"label": f"Due in ≤{config['sla_due_soon_days']} days",
         "value": theme.number((frame["SLA Status"] == "Due soon").sum()), "sub": "act before they breach"},
        {"label": "OS issues", "value": theme.number(os_count), "sub": theme.percent(os_count, len(frame)) + " of findings"},
        {"label": "Application issues", "value": theme.number(len(frame) - os_count),
         "sub": theme.percent(len(frame) - os_count, len(frame)) + " of findings"},
        {"label": "Servers affected", "value": theme.number(frame["Device Name"].nunique()),
         "sub": f"{frame['Applications'].nunique():,} applications"},
    ])

    one, two, three = st.columns(3)
    with one, st.container(border=True):
        theme.title("Severity and SLA status")
        counts = frame.groupby(["Severity", "SLA Status"]).size().reset_index(name="Findings")
        charts.show(charts.stacked_bars(counts, "Severity", "Findings", "SLA Status", charts.SEVERITY_ORDER,
                                        charts.SLA_ORDER, charts.SLA_COLORS, "Open findings"))
    with two, st.container(border=True):
        theme.title("Top applications", "By open findings")
        top = frame.groupby("Applications").size().nlargest(8).reset_index(name="Findings")
        charts.show(charts.ranked_bars(top, "Applications", "Findings", "Open findings"))
    with three, st.container(border=True):
        theme.title("Age of open findings", "Days since first found, by bucket")
        labels = [label for _, _, label in AGE_BUCKETS]
        buckets = pd.cut(frame["Ageing in Days"], bins=[AGE_BUCKETS[0][0]] + [high for _, high, _ in AGE_BUCKETS],
                         labels=labels)
        ages = buckets.value_counts().reindex(labels, fill_value=0).rename_axis("Age").reset_index(name="Findings")
        charts.show(charts.ranked_bars(ages, "Age", "Findings", "Open findings", order=labels))

    # on_change="rerun" makes the tabs lazy: only the open tab's tables are built.
    tabs = st.tabs(["Findings (grouped)", "By server", "All rows"], key="v_tabs", on_change="rerun")
    for tab, body in zip(tabs, (_tab_findings, _tab_servers, _tab_rows)):
        if tab.open:
            with tab:
                body(frame)


def _tab_findings(frame: pd.DataFrame) -> None:
    grouped = _grouped(frame)
    st.caption("Select a row to see the affected servers and ask for a fix.")
    limit = int(settings.load_config()["ui"]["max_table_rows"])
    event = st.dataframe(grouped.head(limit), hide_index=True, on_select="rerun", selection_mode="single-row",
                         key="v_grouped", height=380,
                         column_config={"Finding": st.column_config.TextColumn(width="large")})
    picked = components.selected_row(event)
    if picked is not None and picked < len(grouped):
        _detail(frame, grouped.iloc[picked]["Finding"])


def _tab_servers(frame: pd.DataFrame) -> None:
    flags = frame.assign(_breached=frame["SLA Status"].eq("Breached"),
                         _high=frame["Severity"].isin(["High", "Critical"]),
                         _os=frame["Topic"].eq(classifier.OS))
    servers = flags.groupby(["Device Name", "Applications", "Environment", "Operating System"], dropna=False).agg(
        **{"Open findings": ("Title", "size"), "Past SLA": ("_breached", "sum"),
           "High or critical": ("_high", "sum"), "OS issues": ("_os", "sum"),
           "Oldest (days)": ("Ageing in Days", "max")}).reset_index()
    components.capped_table(servers.sort_values("Past SLA", ascending=False), "v_servers",
                            "vulnerabilities_by_server.csv", height=420)


def _tab_rows(frame: pd.DataFrame) -> None:
    columns = [c for c in ROW_COLUMNS if c in frame.columns]
    components.capped_table(frame[columns].sort_values("Ageing in Days", ascending=False), "v_rows",
                            "open_vulnerabilities.csv", height=420)
