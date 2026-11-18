"""Fix-schedule workflow for one application.

1. build_context()  - what is pending, on which servers, in which environment
2. draft_plan()     - rule-based plan that already obeys the Saudi change-window policy
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
from guardrails.output_checks import enforce_schedule
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


def _pack(servers: list[str], minutes: dict[str, int], slots: list[Slot], parallel: int):
    """Fill windows in order with batches of ``parallel`` servers. Returns (waves, unscheduled)."""
    queue = list(servers)
    waves: list[tuple[Slot, list[str], int]] = []
    for slot in slots:
        if not queue:
            break
        chosen: list[str] = []
        used = 0
        while queue:
            batch = queue[:parallel]
            need = max(minutes[s] for s in batch)
            if chosen and used + need > slot.minutes:
                break
            chosen += batch
            queue = queue[parallel:]
            used += need
        waves.append((slot, chosen, used))
    return waves, queue


def _wave(name: str, environment: str, slot: Slot, servers: list[str], used: int,
          context: dict[str, Any], rationale: str) -> dict[str, Any]:
    bundles = [b for b in BUNDLES if any(b in context["per_server"][s]["bundles"] for s in servers)]
    items = []
    for bundle in bundles:
        on = [s for s in servers if bundle in context["per_server"][s]["bundles"]]
        findings = sum(context["per_server"][s]["bundles"][bundle] for s in on)
        items.append(f"{BUNDLES[bundle]}: {findings} item(s) on {len(on)} server(s)")
    return {
        "name": name, "environment": environment, "slot_id": slot.id, "servers": servers, "work_items": items,
        "estimated_minutes": used, "downtime_expected": "os_patching" in bundles,
        "pre_checks": list(_PRE_CHECKS), "post_checks": list(_POST_CHECKS),
        "rollback": " ".join(_ROLLBACK[b] for b in bundles), "rationale": rationale,
    }


def offered_slots(calendar: SaudiCalendar, policies: dict[str, Any], now: datetime | None = None) -> list[Slot]:
    now = now or calendar.now()
    horizon = int(policies["scheduling"]["horizon_days"])
    return calendar.development_slots(now, horizon) + calendar.production_slots(now, horizon)


def draft_plan(context: dict[str, Any], calendar: SaudiCalendar, policies: dict[str, Any],
               now: datetime | None = None) -> dict[str, Any]:
    """Rule-based schedule: development first, soak, production canary, then the rest."""
    now = now or calendar.now()
    rules = policies["scheduling"]
    parallel = max(1, int(rules["max_parallel_servers"]))
    soak = int(rules["soak_days_before_production"])
    slots = offered_slots(calendar, policies, now)
    dev_slots = [s for s in slots if s.environment == DEV]
    prod_slots = [s for s in slots if s.environment == PROD]
    minutes = _server_minutes(context, policies)
    dev, prod = context["servers"][DEV], context["servers"][PROD]

    waves: list[dict[str, Any]] = []
    unscheduled: list[str] = []
    dev_end = None
    if dev:
        packed, left = _pack(dev, minutes, dev_slots, parallel)
        unscheduled += left
        for index, (slot, servers, used) in enumerate(packed, 1):
            name = "Development" if len(packed) == 1 else f"Development wave {index}"
            waves.append(_wave(name, DEV, slot, servers, used, context,
                               "Development may be changed at any time; working hours keep engineers on hand."))
        dev_end = packed[-1][0].end if packed else None
    if prod:
        earliest = dev_end + timedelta(days=soak) if dev_end else now
        eligible = [s for s in prod_slots if s.start >= earliest]
        canary_count = max(1, round(float(rules["canary_fraction"]) * len(prod))) if len(prod) >= 3 else 0
        canary, rest = prod[:canary_count], prod[canary_count:]
        taken = 0
        if canary:
            packed, left = _pack(canary, minutes, eligible, parallel)
            unscheduled += left
            taken = len(packed)
            for index, (slot, servers, used) in enumerate(packed, 1):
                name = "Production canary" if len(packed) == 1 else f"Production canary {index}"
                waves.append(_wave(name, PROD, slot, servers, used, context,
                                   "A small first wave limits the impact if the change misbehaves."))
        packed, left = _pack(rest, minutes, eligible[taken:], parallel)
        unscheduled += left
        for index, (slot, servers, used) in enumerate(packed, 2 if canary else 1):
            waves.append(_wave(f"Production wave {index}", PROD, slot, servers, used, context,
                               "Outside working hours; batches keep part of the cluster in service."))

    breached = sum(part.get("sla_breached", 0) for part in context["sla"].values())
    risks = []
    if context["assumed_production"]:
        risks.append(f"{context['assumed_production']} server(s) have no confirmed environment and are treated as "
                     "production. Confirm them on the Settings page.")
    if breached:
        risks.append(f"{breached:,} finding(s) are already past their SLA.")
    if prod and not dev:
        risks.append("No development servers are known for this application, so the production canary is the first test.")
    if unscheduled:
        risks.append(f"{len(unscheduled)} server(s) did not fit in the {rules['horizon_days']}-day horizon.")

    summary = (f"{len(dev):,} development and {len(prod):,} production server(s). "
               + ("Development goes first during working hours. " if dev else "")
               + (f"Production follows {soak} day(s) later, " if dev and prod else "Production runs " if prod else "")
               + ("outside Saudi working hours, starting with a canary wave." if prod else ""))
    plan = {"application": context["application"], "source": "rules", "model": "",
            "generated_at": now.isoformat(timespec="minutes"), "summary": summary.strip(), "risks": risks,
            "waves": waves}
    return enforce_schedule(plan, slots, context["servers"], calendar)


# ---------------------------------------------------------------- AI refine ----
def policy_summary(policies: dict[str, Any]) -> str:
    calendar, production, rules = policies["calendar"], policies["production"], policies["scheduling"]
    return "\n".join([
        f"- Time zone {calendar['timezone']}. Working days: {', '.join(calendar['working_days'])}; "
        f"working hours {calendar['working_hours']['start']}–{calendar['working_hours']['end']}.",
        f"- Production windows: every night {production['night_window']['start']}–{production['night_window']['end']}, "
        f"and weekend days {production['weekend_day_window']['start']}–{production['weekend_day_window']['end']}. "
        "No production change on Saudi public holidays.",
        "- Development: any time.",
        f"- Soak between development and production: {rules['soak_days_before_production']} day(s).",
        f"- Canary share of production: {rules['canary_fraction']}. Servers worked in parallel: {rules['max_parallel_servers']}.",
        f"- Minutes per server by work type: {rules['minutes_per_server']}.",
    ])


def refine_with_ai(context: dict[str, Any], draft: dict[str, Any], calendar: SaudiCalendar,
                   policies: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Ask the scheduling agent to improve the draft, then force the answer back onto the policy."""
    now = now or calendar.now()
    slots = offered_slots(calendar, policies, now)
    draft_ids = {wave["slot_id"] for wave in draft["waves"]}
    shown = ([s for s in slots if s.environment == DEV][:6] + [s for s in slots if s.environment == PROD][:16]
             + [s for s in slots if s.id in draft_ids])
    shown = sorted({s.id: s for s in shown}.values(), key=lambda s: s.start)

    limit = int(policies.get("llm_input", {}).get("max_servers_listed", 60))
    model_context = {key: value for key, value in context.items() if key != "per_server"}
    if len(context["per_server"]) <= limit:
        model_context["work_per_server"] = {ip: info["bundles"] for ip, info in context["per_server"].items()}
    model_draft = [{key: wave[key] for key in ("name", "environment", "slot_id", "servers", "work_items",
                                               "estimated_minutes")} for wave in draft["waves"]]

    aliases: dict[str, str] = {}
    mask = bool(policies.get("llm_input", {}).get("mask_ip_addresses"))
    if mask:
        model_context = json.loads(input_checks.mask_ips(json.dumps(model_context, default=str), aliases))
        model_draft = json.loads(input_checks.mask_ips(json.dumps(model_draft, default=str), aliases))

    answer, details = SchedulerAgent().plan(model_context, [s.to_dict() for s in shown], model_draft,
                                            policy_summary(policies))
    if mask:
        answer = json.loads(input_checks.unmask_ips(json.dumps(answer, ensure_ascii=False), aliases))

    plan = {"application": context["application"], "source": "ai", "model": details["model"],
            "generated_at": now.isoformat(timespec="minutes"), **answer}
    return enforce_schedule(plan, slots, context["servers"], calendar)


def plan_table(plan: dict[str, Any]) -> pd.DataFrame:
    """Flat table of the plan for display and CSV export."""
    rows = []
    for wave in plan["waves"]:
        rows.append({
            "Wave": wave["name"], "Environment": wave["environment"], "Start": wave["start"], "End": wave["end"],
            "Window": wave["window_kind"], "Servers": len(wave["servers"]),
            "Estimated minutes": wave.get("estimated_minutes", 0),
            "Downtime": "Yes" if wave.get("downtime_expected") else "No",
            "Work": "; ".join(wave.get("work_items", [])), "Server list": ", ".join(wave["servers"]),
        })
    return pd.DataFrame(rows)

