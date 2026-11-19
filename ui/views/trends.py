"""Trends: what changed since last week, and how the numbers move week by week.

The reports only list what is open or failing, so changes come from comparing two weekly files
(tools/history.py has the rules). Every number follows the sidebar filters.
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

import settings
from tools import data_loader as dl, history
from ui import charts, components, state, theme

_DATE_WORDING = {"Last Scan Date Time": "latest scan", "Evaluation Date": "latest evaluation",
                 dl.FILE_DATE: "workbook saved"}

_BREAKDOWNS = {
    dl.VULN: {"Application": ("Applications",), "Application and severity": ("Applications", "Severity"),
              "Severity": ("Severity",), "Environment": ("Environment",)},
    dl.MBSS: {"Application": ("Applications",), "Application and criticality": ("Applications", "Criticality"),
              "Criticality": ("Criticality",), "Environment": ("Environment",)},
    dl.CS: {"Application": ("Applications",), "Application and control": ("Applications", "Control"),
            "Control": ("Control",), "Environment": ("Environment",)},
}

_DETAIL_COLUMNS = {
    dl.VULN: ["Change", "Change detail", "Applications", "Device Name", "Environment", "Title", "Severity", "Qualys ID",
              "Port Number", "Qualys Status", "SLA Status", "Ageing in Days", "Date First Found"],
    dl.MBSS: ["Change", "Change detail", "Applications", "Device Name", "Environment", "Qualys Control ID",
              "Control Description", "Criticality", "Evaluation Date"],
    dl.CS: ["Change", "Change detail", "Applications", "Device Name", "Host Name", "Environment", "Control",
            "State before", "State", "Status before", "Status"],
}


def _file_line(week: state.Week) -> str:
    parts = []
    for kind in (dl.VULN, dl.MBSS, dl.CS):
        info = week.files.get(kind)
        parts.append(f"{dl.KIND_LABEL[kind]}: {info.path.name} ({_DATE_WORDING[info.date_source]} "
                     f"{info.report_date:%d %b %Y})" if info else f"{dl.KIND_LABEL[kind]}: none")
    return " · ".join(parts)


def _pick(weeks: list[state.Week]) -> tuple[state.Week, state.Week | None]:
    labels = [week.label for week in weeks]
    if st.session_state.get("t_current") not in labels:
        st.session_state.pop("t_current", None)
    left, right = st.columns(2)
    current = weeks[labels.index(left.selectbox("This week", labels, key="t_current"))]
    older = [week for week in weeks if week.start < current.start]
    older_labels = [week.label for week in older]
    if st.session_state.get("t_previous") not in older_labels:
        st.session_state.pop("t_previous", None)   # keep the default: the week just before
    if not older:
        right.selectbox("Compared with", ["No earlier week"], disabled=True, key="t_previous_none")
        st.caption(f"**This week** — {_file_line(current)}")
        return current, None
    previous = older[older_labels.index(right.selectbox("Compared with", older_labels, key="t_previous"))]
    st.caption(f"**This week** — {_file_line(current)}  \n**Compared with** — {_file_line(previous)}")
    return current, previous


def _signed(value: int) -> str:
    return f"{value:+,}" if value else "no change"


def _breakdown(kind: str, scoped: pd.DataFrame, key: str) -> None:
    options = _BREAKDOWNS[kind]
    choice = st.segmented_control("Break down by", list(options), default="Application", key=f"t_by_{key}") or "Application"
    by = [column for column in options[choice] if column in scoped.columns]
    table = history.count_changes(scoped, by)
    components.capped_table(table, f"trends-{key}", f"week_over_week_{key}.csv", height=360)


def _details(kind: str, scoped: pd.DataFrame, key: str, unchanged: str) -> None:
    with st.expander("Items that changed"):
        changed = scoped[scoped["Change"].astype(str) != unchanged]
        columns = [column for column in _DETAIL_COLUMNS[kind] if column in changed.columns]
        components.capped_table(changed[columns].sort_values(["Change", "Applications"]), f"trends-{key}-details",
                                f"week_over_week_{key}_items.csv", height=320)


def _missing(kind: str, current: state.Week, previous: state.Week | None) -> bool:
    if previous is None:
        st.info("There is only one week so far. Add the next (or the previous) weekly reports on the Settings page "
                "to see what changed.")
        return True
    lacking = [week.label for week in (current, previous) if kind not in week.files]
    if lacking:
        st.info(f"No {dl.KIND_LABEL[kind].lower()} for {' or '.join(lacking)}.")
        return True
    return False


def _vulnerabilities(current: state.Week, previous: state.Week | None, data: state.Data) -> None:
    if _missing(dl.VULN, current, previous):
        return
    scoped = state.scoped(state.changes(dl.VULN, current, previous, data))
    if scoped.empty:
        st.caption("No vulnerabilities in this scope in either week.")
        return
    totals = history.count_changes(scoped, by=()).iloc[0]
    detail = scoped.loc[scoped["Change"].astype(str) == history.NEW, "Change detail"].value_counts()
    theme.kpis([
        {"label": "New", "value": theme.number(totals[history.NEW]), "tone": "alert" if totals[history.NEW] else "",
         "sub": f"{detail.get(history.REOPENED, 0):,} re-opened · {detail.get(history.NEW_SERVER, 0):,} on servers new this week"},
        {"label": "Fixed", "value": theme.number(totals[history.FIXED]), "tone": "primary",
         "sub": "gone, and the server is still reported"},
        {"label": "Not rescanned", "value": theme.number(totals[history.NOT_RESCANNED]),
         "sub": "server missing from this week's reports; not counted as fixed"},
        {"label": "Still open", "value": theme.number(totals[history.STILL_OPEN]),
         "sub": f"of {totals['Previous total']:,} open in the week compared with"},
        {"label": "Open now", "value": theme.number(totals["Current total"]),
         "sub": f"{_signed(int(totals['Net change']))} vs the week compared with"},
        {"label": "Past SLA", "value": theme.number(totals["Past SLA now"]), "tone": "alert",
         "sub": f"{_signed(int(totals['Past SLA change']))} (was {totals['Past SLA before']:,})"},
    ])
    st.caption("A finding is one server, Qualys ID and port. Fixed means it left the report while the server is still "
               "in this week's reports (the CS report lists every server). Findings on servers missing from this "
               "week's reports are counted as not rescanned instead.")
    _breakdown(dl.VULN, scoped, "vulnerabilities")
    _details(dl.VULN, scoped, "vulnerabilities", history.STILL_OPEN)


def _mbss(current: state.Week, previous: state.Week | None, data: state.Data) -> None:
    if _missing(dl.MBSS, current, previous):
        return
    scoped = state.scoped(state.changes(dl.MBSS, current, previous, data))
    if scoped.empty:
        st.caption("No failed MBSS checks in this scope in either week.")
        return
    totals = history.count_changes(scoped, by=()).iloc[0]
    theme.kpis([
        {"label": "Newly failing", "value": theme.number(totals[history.NEWLY_FAILING]),
         "tone": "alert" if totals[history.NEWLY_FAILING] else "", "sub": "checks failing now, not before"},
        {"label": "Now passing", "value": theme.number(totals[history.NOW_PASSING]), "tone": "primary",
         "sub": "no longer failing; the server is still reported"},
        {"label": "Not rescanned", "value": theme.number(totals[history.NOT_RESCANNED]),
         "sub": "server missing from this week's reports"},
        {"label": "Still failing", "value": theme.number(totals[history.STILL_FAILING]),
         "sub": f"{_signed(int(totals['Net change']))} failed checks overall"},
    ])
    st.caption("A check is one server and Qualys control ID.")
    _breakdown(dl.MBSS, scoped, "mbss")
    _details(dl.MBSS, scoped, "mbss", history.STILL_FAILING)


def _cs(current: state.Week, previous: state.Week | None, data: state.Data) -> None:
    if _missing(dl.CS, current, previous):
        return
    scoped = state.scoped(state.changes(dl.CS, current, previous, data))
    if scoped.empty:
        st.caption("No CS control gaps in this scope in either week.")
        return
    totals = history.count_changes(scoped, by=()).iloc[0]
    theme.kpis([
        {"label": "New gaps", "value": theme.number(totals[history.NEW_GAP]),
         "tone": "alert" if totals[history.NEW_GAP] else "", "sub": "control missing or partial now, not before"},
        {"label": "Gaps closed", "value": theme.number(totals[history.GAP_CLOSED]), "tone": "primary",
         "sub": "control now in place, excepted or out of scope"},
        {"label": "Not rescanned", "value": theme.number(totals[history.NOT_RESCANNED]),
         "sub": "server missing from this week's CS report"},
        {"label": "Still a gap", "value": theme.number(totals[history.STILL_GAP]),
         "sub": f"{_signed(int(totals['Net change']))} gaps overall"},
    ])
    st.caption("One row per server and control (Gap or Partial counts as a gap).")
    _breakdown(dl.CS, scoped, "cs")
    _details(dl.CS, scoped, "cs", history.STILL_GAP)


_TREND_METRICS = {
    "Open findings": "Open vulnerabilities", "Past SLA": "Vulnerabilities past SLA", "Critical": "Critical",
    "High": "High", "Medium": "Medium", "Low": "Low", "Minimal": "Minimal", "MBSS failed": "MBSS failed checks",
    "MBSS critical": "MBSS critical failed checks", "CS gaps": "CS control gaps",
    "Servers with a CS gap": "Servers with a CS gap",
}


def _trend(weeks: list[state.Week], data: state.Data) -> None:
    with st.container(border=True):
        theme.title("Weekly trend", f"Every weekly file in {settings.data_dir().name}/, in the sidebar scope. "
                                    "A week runs Sunday to Saturday; blank means no file of that kind that week.")
        totals = state.trend(weeks, data)
        if totals.empty:
            st.caption("No readable report files.")
            return
        if len(totals) < 2:
            st.caption("One week so far: the lines fill in as weekly files arrive.")
        left, middle, right = st.columns(3)
        with left:
            theme.title("Vulnerabilities")
            charts.show(charts.trend_lines(totals, ["Open findings", "Past SLA"], [charts.PURPLE, charts.RED], "Findings"))
        with middle:
            theme.title("MBSS")
            charts.show(charts.trend_lines(totals, ["MBSS failed", "MBSS critical"], [charts.PURPLE, charts.RED],
                                           "Failed checks"))
        with right:
            theme.title("CS controls")
            charts.show(charts.trend_lines(totals, ["CS gaps", "Servers with a CS gap"], [charts.PURPLE, charts.AMBER],
                                           "Gaps"))
        table = totals.sort_values("Week", ascending=False).assign(Week=lambda f: f["Week"].dt.strftime("%d %b %Y"))
        table = table.rename(columns={"Week": "Week of", **{k: v for k, v in _TREND_METRICS.items() if k in table}})
        components.capped_table(table, "trends-weekly", "weekly_trend.csv")

        theme.title("By application", "Pick a measure; one column per week, newest first.")
        available = [metric for metric in _TREND_METRICS if metric in totals.columns]
        metric = st.selectbox("Measure", available, format_func=_TREND_METRICS.get, key="t_metric")
        per_app = state.trend(weeks, data, by="Applications")
        pivot = per_app.pivot(index="Applications", columns="Week", values=metric)   # one row per week and app
        pivot = pivot[sorted(pivot.columns, reverse=True)]
        if len(pivot.columns) >= 2:
            pivot.insert(0, "Change", pivot.iloc[:, 0] - pivot.iloc[:, 1])
        pivot = pivot.sort_values(pivot.columns[1] if len(pivot.columns) >= 2 else pivot.columns[0], ascending=False)
        pivot.columns = [c if isinstance(c, str) else f"{c:%d %b %Y}" for c in pivot.columns]
        components.capped_table(pivot.reset_index(), "trends-apps", f"weekly_trend_{metric.lower().replace(' ', '_')}.csv")


def render() -> None:
    data = state.load()
    weeks = state.weeks()
    theme.hero("Week over week", "What changed since last week",
               "New, fixed and still-open findings between two weekly reports, and the weekly trend. "
               "Every number follows the sidebar scope.",
               [("Weeks found", str(len(weeks))), ("Scope:", state.scope_label())])
    if not weeks:
        st.info("No report files were found. Add the weekly Excel reports on the Settings page.")
        return
    current, previous = _pick(weeks)
    st.caption("Other pages use the files chosen on the Settings page (the newest by default).")
    tabs = st.tabs(["Vulnerabilities", "MBSS", "CS controls"])
    with tabs[0]:
        _vulnerabilities(current, previous, data)
    with tabs[1]:
        _mbss(current, previous, data)
    with tabs[2]:
        _cs(current, previous, data)
    _trend(weeks, data)
