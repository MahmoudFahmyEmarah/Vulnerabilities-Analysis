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
from workflows import playbook
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


def _clamp(key: str, cap: int) -> None:
    """Bring a stored number back inside a widget's range before the widget is drawn."""
    if int(st.session_state.get(key, 1)) > cap:
        st.session_state[key] = cap


def _wave_controls(context: dict, policies: dict) -> dict[str, int]:
    """How many waves per environment: one each by default, at most waves.max_total together."""
    limit = workflow.max_waves(policies)
    above = int(policies["scheduling"].get("waves", {}).get("automatic_split_production_above", 10))
    dev_n, prod_n = len(context["servers"][env.DEV]), len(context["servers"][env.PROD])
    one, two, three = st.columns([2.4, 1, 1], vertical_alignment="bottom")
    mode = one.segmented_control(
        "Waves", list(workflow.WAVE_MODES), format_func=workflow.WAVE_MODES.get, default="default",
        key="s_wave_mode",
        help=("**One per environment** (the default): one development wave, then one production wave.  \n"
              f"**Automatic:** production also gets a small first wave (canary) when it has more than {above} "
              "servers.  \n"
              f"**Custom:** choose the waves per environment, {limit} at most in total.  \n"
              "A wave whose servers do not fit in one change window continues in the next free windows.")) or "default"
    custom = {env.DEV: 1, env.PROD: 1}
    if mode == "custom":
        if dev_n:
            cap = max(1, min(dev_n, limit - (1 if prod_n else 0)))
            _clamp("s_waves_dev", cap)
            custom[env.DEV] = int(two.number_input("Development waves", 1, cap, key="s_waves_dev"))
        else:
            two.caption("No development servers")
        if prod_n:
            cap = max(1, min(prod_n, limit - (custom[env.DEV] if dev_n else 0)))
            _clamp("s_waves_prod", cap)
            custom[env.PROD] = int(three.number_input("Production waves", 1, cap, key="s_waves_prod"))
        else:
            three.caption("No production servers")
    return workflow.wave_counts(context, policies, mode, custom)


def _when(value) -> str:
    return f"{value:%a %d %b %Y %H:%M}"


def _show_plan(plan: dict, calendar: SaudiCalendar, context: dict) -> None:
    waves = plan["waves"]
    if not waves:
        st.warning("Nothing could be scheduled. Check that the application has servers with pending work.")
        return
    table = workflow.plan_table(plan)
    production = [w for w in waves if w["environment"] == env.PROD]
    first_night = production[0]["windows"][0] if production else None
    theme.kpis([
        {"label": "Waves", "value": str(len(waves)), "tone": "primary",
         "sub": f"{len(table)} change window(s) · " + ("AI-refined plan" if plan["source"] == "ai" else "rule-based draft")},
        {"label": "Development servers", "value": theme.number(sum(len(w["servers"]) for w in waves if w["environment"] == env.DEV)),
         "sub": "any time"},
        {"label": "Production servers", "value": theme.number(sum(len(w["servers"]) for w in production)),
         "sub": "outside working hours only"},
        {"label": "First production window", "value": f"{first_night['start']:%a %d %b}" if first_night else "–",
         "sub": f"{first_night['start']:%H:%M}–{first_night['end']:%H:%M} Riyadh time" if first_night else "no production servers"},
        {"label": "Finishes", "value": f"{max(w['end'] for w in waves):%a %d %b}",
         "sub": f"{sum(w.get('estimated_minutes', 0) for w in waves) / 60:.1f} h of work estimated"},
    ])

    with st.container(border=True):
        theme.title("Timeline", "Riyadh time. One row per wave and one bar per change window. "
                                "Purple = production (nights and weekends), orange = development.")
        timeline = table.assign(Start=table["Start"].map(lambda d: d.replace(tzinfo=None)),
                                End=table["End"].map(lambda d: d.replace(tzinfo=None)))
        charts.show(charts.gantt(timeline))
        st.markdown(f"**{plan.get('summary', '')}**")
        for risk in plan.get("risks", []):
            st.markdown(f"- {risk}")
        for item in plan.get("guardrail_notes", []):
            st.warning(f"Schedule guardrail: {item}", icon=":material/shield:")

    with st.container(border=True):
        theme.title("Waves", "A wave is one group of servers changed together; it can take more than one window.")
        summary = workflow.wave_table(plan)
        st.dataframe(summary.assign(Starts=summary["Starts"].map(_when), Ends=summary["Ends"].map(_when)),
                     hide_index=True, column_config={"Work": st.column_config.TextColumn(width="large")})
        name = f"{plan['application']}".replace("/", "-").replace(" ", "_")
        export = table.assign(Start=table["Start"].map(lambda d: d.isoformat(timespec="minutes")),
                              End=table["End"].map(lambda d: d.isoformat(timespec="minutes")))
        left, right, _ = st.columns([1.2, 1.4, 2])
        left.download_button("Download schedule (CSV)", export.to_csv(index=False).encode("utf-8-sig"),
                             file_name=f"fix_schedule_{name}.csv", mime="text/csv", width="stretch")
        right.download_button("Download Ansible inventory", playbook.schedule_inventory(plan, context),
                              file_name=f"inventory_{name}.ini", mime="text/plain", width="stretch",
                              icon=":material/terminal:",
                              help="One group per wave and per window (for example wave_1, wave_1_window_2), "
                                   "plus development and production. Use it with a finding's playbook and "
                                   "-e target=wave_1 to run one wave at a time. No credentials are in the file.")
        for wave in waves:
            checks = [calendar.check(wave["environment"], w["start"], w["end"]) for w in wave["windows"]]
            failing = [why for allowed, why in checks if not allowed]
            with st.expander(f"{wave['name']} · {wave['window']} · {len(wave['servers'])} server(s)"):
                theme.badges([(wave["environment"], "solid" if wave["environment"] == env.PROD else "orange"),
                              (f"{len(wave['windows'])} window(s)", ""),
                              (f"Policy check: {failing[0] if failing else checks[0][1]}", "red" if failing else "gray"),
                              ("Downtime expected" if wave.get("downtime_expected") else "No downtime expected",
                               "red" if wave.get("downtime_expected") else "gray")])
                if wave.get("rationale"):
                    st.markdown(f"*{wave['rationale']}*")
                left, right = st.columns(2)
                left.markdown("**Work**\n" + ("\n".join(f"- {item}" for item in wave.get("work_items", [])) or "–"))
                right.markdown("**Before**\n" + "\n".join(f"- {item}" for item in wave.get("pre_checks", [])))
                right.markdown("**After**\n" + "\n".join(f"- {item}" for item in wave.get("post_checks", [])))
                if wave.get("rollback"):
                    right.markdown(f"**Roll back.** {wave['rollback']}")
                for number, window in enumerate(wave["windows"], 1):
                    left.markdown(f"**Window {number}** · {window['window']} · {window['window_kind']} · "
                                  f"{len(window['servers'])} server(s), about {window['estimated_minutes']} of "
                                  f"{window['window_minutes']} min")
                    left.code(", ".join(window["servers"]), language=None, wrap_lines=True)


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
        counts = _wave_controls(context, policies)

    work = pd.DataFrame([{"Environment": environment, "Work": workflow.BUNDLES[bundle], "Servers": numbers["servers"],
                          "Items": numbers["findings"]}
                         for environment, bundles in context["workload"].items()
                         for bundle, numbers in bundles.items() if numbers["servers"]])
    with st.expander("Pending work for this application", expanded=False):
        st.dataframe(work, hide_index=True)
        if context["assumed_production"]:
            st.caption(f"{context['assumed_production']} server(s) have no confirmed environment and are treated as production.")

    wave_key = f"{counts[env.DEV]}+{counts[env.PROD]}"
    plan_key = f"plan::{application}::{'|'.join(sorted(include))}::{wave_key}"
    draft = workflow.draft_plan(context, calendar, policies, counts=counts)
    # A refined plan is kept only for the servers, the waves and the day it was made for: a change of scope,
    # a new report or a new day brings back the draft, so an old plan with past windows is never shown.
    signature = (tuple(context["servers"][env.DEV]), tuple(context["servers"][env.PROD]), wave_key,
                 f"{calendar.now():%Y-%m-%d}")
    saved = st.session_state.get(plan_key)
    if saved and saved["signature"] != signature:
        st.session_state.pop(plan_key, None)
        saved = None
        st.caption("The AI-refined plan was made for other servers or another day, so the draft is shown again.")
    plan = saved["plan"] if saved else draft

    left, middle, _ = st.columns([1.3, 1.3, 4])
    configured = base_agent.is_configured()
    if left.button("Refine with AI", type="primary", icon=":material/auto_awesome:", disabled=not configured,
                   key="s_refine", width="stretch"):
        try:
            with st.spinner("The scheduling agent is reviewing the draft…"):
                plan = workflow.refine_with_ai(context, draft, calendar, policies, counts=counts)
            st.session_state[plan_key] = {"plan": plan, "signature": signature}
        except AgentError as error:
            st.error(str(error))
    if middle.button("Back to the draft", disabled=plan_key not in st.session_state, key="s_reset", width="stretch"):
        st.session_state.pop(plan_key, None)
        plan = draft
    if not configured:
        st.caption("No model endpoint is configured, so this is the rule-based draft. Add the endpoint on the Settings page.")

    _show_plan(plan, calendar, context)

    with st.expander("Next production windows and holidays"):
        slots = calendar.production_slots(calendar.now(), 14)
        st.dataframe(pd.DataFrame([{"Window": slot.label, "Type": slot.kind, "Hours": round(slot.minutes / 60, 1)}
                                   for slot in slots]), hide_index=True)
        holidays = calendar.upcoming_holidays(calendar.now().date(), 200)
        if holidays:
            st.markdown("**Production freeze days in the next 200 days:** "
                        + ", ".join(f"{day:%d %b %Y} ({name})" for day, name in holidays))
        st.caption("Eid dates are astronomical estimates. Correct or add dates in guardrails/policies.yaml.")
