"""Fix schedule: plan when to fix one application, development first, production outside Saudi working hours."""
from __future__ import annotations

import pandas as pd
import streamlit as st

import settings
from agents import base_agent
from agents.base_agent import AgentError
from tools import environment as env
from tools.saudi_calendar import SaudiCalendar
from ui import charts, state, theme
from workflows import schedule as workflow

SOURCES = {"Vulnerabilities": "vulns", "MBSS": "mbss", "CS controls": "cs"}


def _applications(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame) -> list[str]:
    """Applications with pending work, most findings past SLA first."""
    score: dict[str, float] = {}
    if not vulns.empty:
        for app, count in vulns[vulns["SLA Status"] == "Breached"].groupby("Applications").size().items():
            score[app] = score.get(app, 0) + count * 1000
        for app, count in vulns.groupby("Applications").size().items():
            score[app] = score.get(app, 0) + count
    for frame in (mbss, cs[cs["Gaps"] > 0] if not cs.empty else cs):
        if not frame.empty:
            for app, count in frame.groupby("Applications").size().items():
                score[app] = score.get(app, 0) + count
    return sorted(score, key=score.get, reverse=True)


def _show_plan(plan: dict, calendar: SaudiCalendar) -> None:
    waves = plan["waves"]
    if not waves:
        st.warning("Nothing could be scheduled. Check that the application has servers with pending work.")
        return
    table = workflow.plan_table(plan)
    production = [w for w in waves if w["environment"] == env.PROD]
    theme.kpis([
        {"label": "Waves", "value": str(len(waves)), "tone": "primary",
         "sub": "AI-refined plan" if plan["source"] == "ai" else "Rule-based draft"},
        {"label": "Development servers", "value": theme.number(sum(len(w["servers"]) for w in waves if w["environment"] == env.DEV)),
         "sub": "any time"},
        {"label": "Production servers", "value": theme.number(sum(len(w["servers"]) for w in production)),
         "sub": "outside working hours only"},
        {"label": "First production window", "value": f"{production[0]['start']:%a %d %b}" if production else "–",
         "sub": f"{production[0]['start']:%H:%M}–{production[0]['end']:%H:%M} Riyadh time" if production else "no production servers"},
        {"label": "Finishes", "value": f"{max(w['end'] for w in waves):%a %d %b}",
         "sub": f"{sum(w.get('estimated_minutes', 0) for w in waves) / 60:.1f} h of work estimated"},
    ])

    with st.container(border=True):
        theme.title("Timeline", "Riyadh time. Purple = production (nights and weekends), orange = development.")
        timeline = table.assign(Start=table["Start"].map(lambda d: d.replace(tzinfo=None)),
                                End=table["End"].map(lambda d: d.replace(tzinfo=None)))
        charts.show(charts.gantt(timeline))
        st.markdown(f"**{plan.get('summary', '')}**")
        for risk in plan.get("risks", []):
            st.markdown(f"- {risk}")
        for item in plan.get("guardrail_notes", []):
            st.warning(f"Schedule guardrail: {item}", icon=":material/shield:")

    with st.container(border=True):
        theme.title("Waves")
        display = table.drop(columns=["Server list"]).assign(
            Start=table["Start"].map(lambda d: f"{d:%a %d %b %Y %H:%M}"),
            End=table["End"].map(lambda d: f"{d:%a %d %b %Y %H:%M}"))
        st.dataframe(display, hide_index=True, column_config={"Work": st.column_config.TextColumn(width="large")})
        export = table.assign(Start=table["Start"].map(lambda d: d.isoformat(timespec="minutes")),
                              End=table["End"].map(lambda d: d.isoformat(timespec="minutes")))
        st.download_button("Download schedule (CSV)", export.to_csv(index=False).encode("utf-8-sig"),
                           file_name=f"fix_schedule_{plan['application']}.csv".replace("/", "-").replace(" ", "_"),
                           mime="text/csv")
        for wave in waves:
            allowed, reason = calendar.check(wave["environment"], wave["start"], wave["end"])
            with st.expander(f"{wave['name']} · {wave['window']} · {len(wave['servers'])} server(s)"):
                theme.badges([(wave["environment"], "solid" if wave["environment"] == env.PROD else "orange"),
                              (wave["window_kind"], ""), (f"Policy check: {reason}", "gray" if allowed else "red"),
                              ("Downtime expected" if wave.get("downtime_expected") else "No downtime expected",
                               "red" if wave.get("downtime_expected") else "gray")])
                if wave.get("rationale"):
                    st.markdown(f"*{wave['rationale']}*")
                left, right = st.columns(2)
                left.markdown("**Work**\n" + "\n".join(f"- {item}" for item in wave.get("work_items", [])) or "–")
                left.markdown("**Servers**")
                left.code(", ".join(wave["servers"]), language=None, wrap_lines=True)
                right.markdown("**Before**\n" + "\n".join(f"- {item}" for item in wave.get("pre_checks", [])))
                right.markdown("**After**\n" + "\n".join(f"- {item}" for item in wave.get("post_checks", [])))
                if wave.get("rollback"):
                    right.markdown(f"**Roll back.** {wave['rollback']}")


def render() -> None:
    data = state.load()
    vulns, mbss, cs, _ = state.filtered(data)
    policies = settings.load_policies()
    calendar = SaudiCalendar(policies)
    hours = policies["calendar"]["working_hours"]
    theme.hero(
        "Fix schedule · Saudi change calendar",
        "Plan the fixes for an application",
        f"Development servers can be changed at any time. Production servers are only scheduled outside working hours "
        f"({', '.join(day[:3] for day in policies['calendar']['working_days'])} {hours['start']}–{hours['end']}, "
        "Asia/Riyadh) and never on Saudi public holidays. The AI decides grouping and order; the calendar decides the times.",
        [("Now in Riyadh:", f"{calendar.now():%a %d %b %H:%M}"), ("Scope:", state.scope_label())],
    )

    applications = _applications(vulns, mbss, cs)
    if not applications:
        st.info("No application in this scope has pending work.")
        return
    with st.container(border=True):
        one, two = st.columns([2, 2])
        application = one.selectbox("Application", applications, key="s_app",
                                    help="Sorted by findings past SLA, then by open items.")
        include = two.pills("Include", list(SOURCES), selection_mode="multi", default=list(SOURCES), key="s_include")
    include = include or list(SOURCES)
    empty = pd.DataFrame()
    selected = {
        "vulns": vulns[vulns["Applications"] == application] if "Vulnerabilities" in include and not vulns.empty else empty,
        "mbss": mbss[mbss["Applications"] == application] if "MBSS" in include and not mbss.empty else empty,
        "cs": cs[cs["Applications"] == application] if "CS controls" in include and not cs.empty else empty,
    }
    context = workflow.build_context(application, selected["vulns"], selected["mbss"], selected["cs"])
    if not context["per_server"]:
        st.info("This application has no pending work for the selected checks.")
        return

    work = pd.DataFrame([{"Environment": environment, "Work": workflow.BUNDLES[bundle], "Servers": numbers["servers"],
                          "Items": numbers["findings"]}
                         for environment, bundles in context["workload"].items()
                         for bundle, numbers in bundles.items() if numbers["servers"]])
    with st.expander("Pending work for this application", expanded=False):
        st.dataframe(work, hide_index=True)
        if context["assumed_production"]:
            st.caption(f"{context['assumed_production']} server(s) have no confirmed environment and are treated as production.")

    plan_key = f"plan::{application}::{'|'.join(sorted(include))}"
    draft = workflow.draft_plan(context, calendar, policies)
    plan = st.session_state.get(plan_key, draft)

    left, middle, _ = st.columns([1.3, 1.3, 4])
    configured = base_agent.is_configured()
    if left.button("Refine with AI", type="primary", icon=":material/auto_awesome:", disabled=not configured,
                   key="s_refine", width="stretch"):
        try:
            with st.spinner("The scheduling agent is reviewing the draft…"):
                plan = workflow.refine_with_ai(context, draft, calendar, policies)
            st.session_state[plan_key] = plan
        except AgentError as error:
            st.error(str(error))
    if middle.button("Back to the draft", disabled=plan_key not in st.session_state, key="s_reset", width="stretch"):
        st.session_state.pop(plan_key, None)
        plan = draft
    if not configured:
        st.caption("No model endpoint is configured, so this is the rule-based draft. Add the endpoint on the Settings page.")

    _show_plan(plan, calendar)

    with st.expander("Next production windows and holidays"):
        slots = calendar.production_slots(calendar.now(), 14)
        st.dataframe(pd.DataFrame([{"Window": slot.label, "Type": slot.kind, "Hours": round(slot.minutes / 60, 1)}
                                   for slot in slots]), hide_index=True)
        holidays = calendar.upcoming_holidays(calendar.now().date(), 200)
        if holidays:
            st.markdown("**Production freeze days in the next 200 days:** "
                        + ", ".join(f"{day:%d %b %Y} ({name})" for day, name in holidays))
        st.caption("Eid dates are astronomical estimates. Correct or add dates in guardrails/policies.yaml.")
