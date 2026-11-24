"""Fix-schedule workflow for one application.

1. build_context()  - what is pending, on which servers, in which environment
2. draft_plan()     - rule-based plan in 2 to 4 waves (wave_counts) that already obeys the policy
3. refine_with_ai() - the scheduling agent improves grouping and sequencing
4. enforce_schedule (guardrail) - every plan, drafted or refined, is forced back onto
   valid windows, so production is never scheduled inside working hours.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import pandas as pd

from agents.scheduler import SchedulerAgent
from guardrails import input_checks
from guardrails.output_checks import MAX_WAVES, enforce_schedule, strip_images, wave_limits
from tools.environment import DEV, PROD, SRC_ASSUMED
from tools.saudi_calendar import SaudiCalendar, Slot

BUNDLES = {
    "os_patching": "OS patching",
    "application_fix": "Application fixes",
    "mbss_hardening": "MBSS hardening",
    "cs_control": "Security control onboarding",
}
_ROLLBACK = {
    "os_patching": "Undo the package transaction (dnf history undo) or boot the previous kernel; on Windows uninstall the update.",
    "application_fix": "Restore the previous application version or library from the backup taken before the change.",
    "mbss_hardening": "Restore the configuration files or policy export saved before the change.",
    "cs_control": "Stop and uninstall the agent, or revert the log-forwarding / access configuration.",
}
_PRE_CHECKS = ["Change request approved", "Service and cluster health is green",
               "Backup, snapshot or configuration export taken"]
_POST_CHECKS = ["Service and cluster health is green", "Application owner confirms normal behaviour",
                "Re-scan requested to close the findings"]


def _ip_sort(ip: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in str(ip).split("."))


# ------------------------------------------------------------------ context ----
def build_context(application: str, vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame) -> dict[str, Any]:
    """Summarise pending work for one application. Frames must already be filtered to it."""
    per_server: dict[str, dict[str, Any]] = {}

    def touch(frame: pd.DataFrame) -> None:
        columns = ["Device Name", "Environment", "Env Source"]
        for ip, environment, source in frame[columns].drop_duplicates("Device Name").itertuples(index=False):
            per_server.setdefault(ip, {"environment": environment, "env_source": source, "bundles": {}})

    def add(frame: pd.DataFrame, bundle: str) -> None:
        for ip, count in frame.groupby("Device Name").size().items():
            per_server[ip]["bundles"][bundle] = int(count)

    top_items: dict[str, list[dict[str, Any]]] = {}
    sla: dict[str, dict[str, Any]] = {}
    if not vulns.empty:
        touch(vulns)
        add(vulns[vulns["Topic"] == "OS Issue"], "os_patching")
        add(vulns[vulns["Topic"] != "OS Issue"], "application_fix")
        for bundle, part in (("os_patching", vulns[vulns["Topic"] == "OS Issue"]),
                             ("application_fix", vulns[vulns["Topic"] != "OS Issue"])):
            grouped = part.groupby("Title").agg(servers=("Device Name", "nunique"), severity=("Severity", "first"),
                                                breached=("SLA Status", lambda s: int((s == "Breached").sum())))
            top_items[bundle] = [{"item": title, **row} for title, row in
                                 grouped.sort_values("servers", ascending=False).head(6).to_dict("index").items()]
        for environment, part in vulns.groupby("Environment"):
            sla[environment] = {"open_findings": int(len(part)),
                                "sla_breached": int((part["SLA Status"] == "Breached").sum()),
                                "due_soon": int((part["SLA Status"] == "Due soon").sum()),
                                "by_severity": part["Severity"].value_counts().to_dict()}
        os_mix = vulns.drop_duplicates("Device Name")["OS Family"].value_counts().to_dict()
    else:
        os_mix = {}
    if not mbss.empty:
        touch(mbss)
        add(mbss, "mbss_hardening")
        grouped = mbss.groupby("Control Description").agg(servers=("Device Name", "nunique"),
                                                          criticality=("Criticality", "first"))
        top_items["mbss_hardening"] = [{"item": str(title)[:160], **row} for title, row in
                                       grouped.sort_values("servers", ascending=False).head(6).to_dict("index").items()]
    if not cs.empty:
        touch(cs)
        gaps = cs[cs["Gaps"] > 0]
        for ip, count in zip(gaps["Device Name"], gaps["Gaps"]):
            per_server[ip]["bundles"]["cs_control"] = int(count)
        state_columns = [c for c in cs.columns if c.endswith(" State")]
        top_items["cs_control"] = [
            {"item": column.removesuffix(" State"), "servers": int(cs[column].isin(["Gap", "Partial"]).sum())}
            for column in state_columns if cs[column].isin(["Gap", "Partial"]).any()]

    per_server = {ip: info for ip, info in per_server.items() if info["bundles"]}
    servers = {env: sorted((ip for ip, info in per_server.items() if info["environment"] == env), key=_ip_sort)
               for env in (DEV, PROD)}
    workload = {env: {bundle: {"servers": sum(1 for ip in servers[env] if bundle in per_server[ip]["bundles"]),
                               "findings": sum(per_server[ip]["bundles"].get(bundle, 0) for ip in servers[env])}
                      for bundle in BUNDLES} for env in (DEV, PROD)}
    return {
        "application": application,
        "servers": servers,
        "per_server": per_server,
        "workload": workload,
        "sla": sla,
        "top_items": top_items,
        "os_mix": os_mix,
        "assumed_production": sum(1 for info in per_server.values() if info["env_source"] == SRC_ASSUMED),
    }


# -------------------------------------------------------------------- draft ----
def _server_minutes(context: dict[str, Any], policies: dict[str, Any]) -> dict[str, int]:
    cost = policies["scheduling"]["minutes_per_server"]
    return {ip: sum(int(cost.get(bundle, 30)) for bundle in info["bundles"])
            for ip, info in context["per_server"].items()}


WAVE_MODES = {
    "default": "One per environment",
    "automatic": "Automatic",
    "custom": "Custom",
}


def _wave_rules(policies: dict[str, Any]) -> dict[str, Any]:
    return policies["scheduling"].get("waves", {}) or {}


def max_waves(policies: dict[str, Any]) -> int:
    return int(_wave_rules(policies).get("max_total", MAX_WAVES))


def wave_counts(context: dict[str, Any], policies: dict[str, Any], mode: str = "default",
                custom: dict[str, int] | None = None) -> dict[str, int]:
    """Waves per environment for this application.

    default   - waves.default in policies.yaml: one development and one production wave.
    automatic - one development wave; production gets a small first (canary) wave as well when it has
                more than waves.automatic_split_production_above servers.
    custom    - what the user picked. Always at least one wave per environment that has servers and at
                most waves.max_total together (wave_limits).
    """
    rules = _wave_rules(policies)
    if mode == "custom" and custom:
        wanted = {DEV: int(custom.get(DEV, 1)), PROD: int(custom.get(PROD, 1))}
    elif mode == "automatic":
        above = int(rules.get("automatic_split_production_above", 10))
        wanted = {DEV: 1, PROD: 2 if len(context["servers"][PROD]) > above else 1}
    else:
        default = rules.get("default", {}) or {}
        wanted = {DEV: int(default.get(DEV, 1)), PROD: int(default.get(PROD, 1))}
    return wave_limits(wanted, context["servers"], max_waves(policies))


def _split(servers: list[str], count: int, first_share: float | None = None) -> list[list[str]]:
    """Cut ``servers`` into ``count`` groups in order; ``first_share`` makes the first one smaller (a canary)."""
    rest = list(servers)
    if count <= 1 or len(rest) <= 1:
        return [rest] if rest else []
    groups: list[list[str]] = []
    if first_share is not None:
        first = max(1, min(len(rest) - (count - 1), round(first_share * len(rest))))
        groups.append(rest[:first])
        rest, count = rest[first:], count - 1
    size, extra = divmod(len(rest), count)
    start = 0
    for index in range(count):
        end = start + size + (1 if index < extra else 0)
        groups.append(rest[start:end])
        start = end
    return [group for group in groups if group]


def _guard(plan: dict[str, Any], slots: list[Slot], context: dict[str, Any], calendar: SaudiCalendar,
           policies: dict[str, Any], counts: dict[str, int]) -> dict[str, Any]:
    """Run the schedule guardrail with this application's work estimates and wave counts."""
    rules = policies["scheduling"]
    return enforce_schedule(plan, slots, context["servers"], calendar,
                            minutes=_server_minutes(context, policies),
                            parallel=max(1, int(rules["max_parallel_servers"])),
                            soak_days=int(rules["soak_days_before_production"]),
                            waves_per_env=counts, max_waves=max_waves(policies))


def _wave(name: str, environment: str, servers: list[str], context: dict[str, Any], rationale: str) -> dict[str, Any]:
    """A drafted wave. It has no window yet: the guardrail gives it the next free ones."""
    bundles = [b for b in BUNDLES if any(b in context["per_server"][s]["bundles"] for s in servers)]
    items = []
    for bundle in bundles:
        on = [s for s in servers if bundle in context["per_server"][s]["bundles"]]
        findings = sum(context["per_server"][s]["bundles"][bundle] for s in on)
        items.append(f"{BUNDLES[bundle]}: {findings} item(s) on {len(on)} server(s)")
    return {
        "name": name, "environment": environment, "slot_id": "", "servers": servers, "work_items": items,
        "downtime_expected": "os_patching" in bundles,
        "pre_checks": list(_PRE_CHECKS), "post_checks": list(_POST_CHECKS),
        "rollback": " ".join(_ROLLBACK[b] for b in bundles), "rationale": rationale,
    }


def _wave_name(environment: str, index: int, total: int) -> tuple[str, str]:
    if environment == DEV:
        return ("Development" if total == 1 else f"Development wave {index}",
                "Development may be changed at any time; working hours keep engineers on hand.")
    if total == 1:
        return "Production", "Outside working hours; batches keep part of the cluster in service."
    if index == 1:
        return "Production wave 1 (canary)", "A small first wave limits the impact if the change misbehaves."
    return f"Production wave {index}", "Outside working hours, after the previous wave has gone well."


def offered_slots(calendar: SaudiCalendar, policies: dict[str, Any], now: datetime | None = None) -> list[Slot]:
    now = now or calendar.now()
    horizon = int(policies["scheduling"]["horizon_days"])
    return calendar.development_slots(now, horizon) + calendar.production_slots(now, horizon)


def draft_plan(context: dict[str, Any], calendar: SaudiCalendar, policies: dict[str, Any],
               now: datetime | None = None, counts: dict[str, int] | None = None) -> dict[str, Any]:
    """Rule-based schedule: development first, soak, then production, in ``counts`` waves per environment.

    With two or more production waves the first is a small canary. The guardrail then gives every wave
    the next free windows of its environment; a wave whose servers do not fit in one window runs over
    several.
    """
    now = now or calendar.now()
    rules = policies["scheduling"]
    soak = int(rules["soak_days_before_production"])
    counts = counts or wave_counts(context, policies)
    dev, prod = context["servers"][DEV], context["servers"][PROD]

    waves: list[dict[str, Any]] = []
    for environment, servers in ((DEV, dev), (PROD, prod)):
        share = float(rules["canary_fraction"]) if environment == PROD else None
        groups = _split(servers, counts.get(environment, 1), share)
        for index, group in enumerate(groups, 1):
            name, rationale = _wave_name(environment, index, len(groups))
            waves.append(_wave(name, environment, group, context, rationale))

    breached = sum(part.get("sla_breached", 0) for part in context["sla"].values())
    risks = []
    if context["assumed_production"]:
        risks.append(f"{context['assumed_production']} server(s) have no confirmed environment and are treated as "
                     "production. Confirm them on the Settings page.")
    if breached:
        risks.append(f"{breached:,} finding(s) are already past their SLA.")
    if prod and not dev:
        risks.append("No development servers are known for this application, so the first production wave is the "
                     "first test.")

    production_waves = counts.get(PROD, 0) if prod else 0
    summary = (f"{len(dev):,} development and {len(prod):,} production server(s) in {len(waves)} wave(s). "
               + ("Development goes first during working hours. " if dev else "")
               + (f"Production follows {soak} day(s) later, " if dev and prod else "Production runs " if prod else "")
               + ("outside Saudi working hours" if prod else "")
               + (", starting with a small canary wave." if production_waves > 1 else "." if prod else ""))
    plan = {"application": context["application"], "source": "rules", "model": "",
            "generated_at": now.isoformat(timespec="minutes"), "summary": summary.strip(), "risks": risks,
            "waves": waves}
    return _guard(plan, offered_slots(calendar, policies, now), context, calendar, policies, counts)


# ---------------------------------------------------------------- AI refine ----
def policy_summary(policies: dict[str, Any], counts: dict[str, int] | None = None) -> str:
    calendar, production, rules = policies["calendar"], policies["production"], policies["scheduling"]
    lines = [
        f"- Time zone {calendar['timezone']}. Working days: {', '.join(calendar['working_days'])}; "
        f"working hours {calendar['working_hours']['start']}–{calendar['working_hours']['end']}.",
        f"- Production windows: every night {production['night_window']['start']}–{production['night_window']['end']}, "
        f"and weekend days {production['weekend_day_window']['start']}–{production['weekend_day_window']['end']}. "
        "No production change on Saudi public holidays.",
        "- Development: any time.",
        f"- Soak between development and production: {rules['soak_days_before_production']} day(s).",
        f"- Servers worked in parallel: {rules['max_parallel_servers']}.",
        f"- Minutes per server by work type: {rules['minutes_per_server']}.",
    ]
    if counts is not None:
        lines.append(
            f"- Waves: exactly {counts.get(DEV, 0)} development and {counts.get(PROD, 0)} production wave(s), "
            f"{max_waves(policies)} at most in total. A wave may need more than one window: give the slot_id of the "
            "window it starts in and the calendar continues it in the next free windows of its environment. With two "
            f"or more production waves the first is a small canary (about {rules['canary_fraction']} of the "
            "production servers).")
    return "\n".join(lines)


def _window_ids(plan: dict[str, Any]) -> set[str]:
    return {window["slot_id"] for wave in plan["waves"] for window in wave.get("windows", [])}


def refine_with_ai(context: dict[str, Any], draft: dict[str, Any], calendar: SaudiCalendar,
                   policies: dict[str, Any], now: datetime | None = None,
                   counts: dict[str, int] | None = None) -> dict[str, Any]:
    """Ask the scheduling agent to improve the draft, then force the answer back onto the policy."""
    now = now or calendar.now()
    counts = counts or wave_counts(context, policies)
    slots = offered_slots(calendar, policies, now)
    draft_ids = _window_ids(draft)
    shown = ([s for s in slots if s.environment == DEV][:6] + [s for s in slots if s.environment == PROD][:16]
             + [s for s in slots if s.id in draft_ids])
    shown = sorted({s.id: s for s in shown}.values(), key=lambda s: s.start)

    limit = int(policies.get("llm_input", {}).get("max_servers_listed", 60))
    model_context = {key: value for key, value in context.items() if key != "per_server"}
    if len(context["per_server"]) <= limit:
        model_context["work_per_server"] = {ip: info["bundles"] for ip, info in context["per_server"].items()}
    model_draft = [{**{key: wave[key] for key in ("name", "environment", "slot_id", "servers", "work_items",
                                                  "estimated_minutes")},
                    "windows_used": len(wave.get("windows", []))} for wave in draft["waves"]]

    aliases: dict[str, str] = {}
    mask = bool(policies.get("llm_input", {}).get("mask_ip_addresses"))
    if mask:
        model_context = json.loads(input_checks.mask_ips(json.dumps(model_context, default=str), aliases))
        model_draft = json.loads(input_checks.mask_ips(json.dumps(model_draft, default=str), aliases))

    answer, details = SchedulerAgent().plan(model_context, [s.to_dict() for s in shown], model_draft,
                                            policy_summary(policies, counts))
    if mask:
        answer = json.loads(input_checks.unmask_ips(json.dumps(answer, ensure_ascii=False), aliases))
    answer = strip_images(answer)

    plan = {"application": context["application"], "source": "ai", "model": details["model"],
            "generated_at": now.isoformat(timespec="minutes"), **answer}
    return _guard(plan, slots, context, calendar, policies, counts)


def plan_table(plan: dict[str, Any]) -> pd.DataFrame:
    """One row per change window of every wave, for the timeline and the CSV export."""
    rows = []
    for wave in plan["waves"]:
        windows = wave.get("windows", [])
        for number, window in enumerate(windows, 1):
            rows.append({
                "Wave": wave["name"], "Environment": wave["environment"],
                "Window": f"{number} of {len(windows)}", "Start": window["start"], "End": window["end"],
                "Window type": window["window_kind"], "Servers": len(window["servers"]),
                "Estimated minutes": window["estimated_minutes"], "Window minutes": window["window_minutes"],
                "Downtime": "Yes" if wave.get("downtime_expected") else "No",
                "Work": "; ".join(wave.get("work_items", [])), "Server list": ", ".join(window["servers"]),
            })
    return pd.DataFrame(rows)


def wave_table(plan: dict[str, Any]) -> pd.DataFrame:
    """One row per wave."""
    return pd.DataFrame([{
        "Wave": wave["name"], "Environment": wave["environment"], "Windows": len(wave.get("windows", [])),
        "Starts": wave["start"], "Ends": wave["end"], "Servers": len(wave["servers"]),
        "Estimated hours": round(wave.get("estimated_minutes", 0) / 60, 1),
        "Downtime": "Yes" if wave.get("downtime_expected") else "No", "Work": "; ".join(wave.get("work_items", [])),
    } for wave in plan["waves"]])
