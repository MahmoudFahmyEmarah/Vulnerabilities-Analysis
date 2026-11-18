"""Checks on what the model returns before an engineer sees it.

* review_recommendation: flags commands that are destructive or need a second look.
* enforce_schedule: rebuilds a model-proposed schedule so that it obeys the change-window
  policy no matter what the model wrote. Dates and times always come from calendar slots.
"""
from __future__ import annotations

import re
from typing import Any

from tools.environment import DEV, PROD
from tools.saudi_calendar import SaudiCalendar, Slot

_RISKY_COMMANDS = [
    (r"\brm\s+-[a-z]*r[a-z]*f?\s+/(?:\s|$|\*)", "deletes from the filesystem root"),
    (r"\bmkfs\b|\bdd\s+if=|\bfdisk\b|\bparted\b|\bwipefs\b", "rewrites a disk or filesystem"),
    (r"\bchmod\s+(-R\s+)?777\b", "opens permissions to everyone"),
    (r"curl[^|\n]*\|\s*(sudo\s+)?(ba)?sh|wget[^|\n]*\|\s*(sudo\s+)?(ba)?sh", "pipes a download straight into a shell"),
    (r"\bsetenforce\s+0\b|SELINUX=disabled", "turns SELinux off"),
    (r"systemctl\s+(stop|disable)\s+(firewalld|auditd)|\biptables\s+-F\b|ufw\s+disable", "disables a security service"),
    (r"--nogpgcheck|gpgcheck\s*=\s*0", "skips package signature checks"),
    (r"\bDROP\s+(DATABASE|TABLE)\b|\bTRUNCATE\s+TABLE\b", "destroys database objects"),
]
_RESTART = re.compile(r"\b(reboot|shutdown\s+-r|init\s+6|Restart-Computer|systemctl\s+reboot)\b", re.IGNORECASE)


def review_recommendation(recommendation: dict[str, Any]) -> list[str]:
    """Return human-readable warnings for a recommendation (empty list = nothing flagged)."""
    warnings: list[str] = []
    commands = [command for step in recommendation.get("steps", []) for command in step.get("commands", [])]
    commands += recommendation.get("rollback", []) + recommendation.get("verification", [])
    for pattern, meaning in _RISKY_COMMANDS:
        hits = [c for c in commands if re.search(pattern, c, re.IGNORECASE)]
        if hits:
            warnings.append(f"A command {meaning}: `{hits[0][:120]}`. Review before running.")
    if any(_RESTART.search(c) for c in commands) and recommendation.get("restart_required") != "host":
        warnings.append("The steps reboot the host but the answer does not declare a host restart. "
                        "Treat this fix as needing downtime.")
    if not commands:
        warnings.append("No commands were given. Treat the steps as guidance and confirm details with the vendor advisory.")
    return warnings


def _environment(text: str) -> str:
    return DEV if str(text).strip().lower().startswith(("dev", "non", "test", "pre")) else PROD


def enforce_schedule(
    plan: dict[str, Any],
    slots: list[Slot],
    servers_by_env: dict[str, list[str]],
    calendar: SaudiCalendar,
) -> dict[str, Any]:
    """Make a proposed plan obey the policy. Returns the corrected plan with 'guardrail_notes'.

    Rules applied:
      1. A wave's time comes from its slot; an unknown slot is replaced by the next free valid one.
      2. A production wave must sit in a production window that passes calendar.check().
      3. Only servers that belong to the application and to the wave's environment are kept;
         each server appears once; servers the model forgot are added to a final wave.
    """
    notes: list[str] = []
    by_id = {slot.id: slot for slot in slots}
    free = {env: [slot for slot in slots if slot.environment == env] for env in (PROD, DEV)}
    used: set[str] = set()
    remaining = {env: list(servers) for env, servers in servers_by_env.items()}
    waves: list[dict[str, Any]] = []

    def next_free(environment: str, not_before=None) -> Slot | None:
        for slot in free.get(environment, []):
            if slot.id not in used and (not_before is None or slot.start >= not_before):
                return slot
        return None

    for wave in plan.get("waves", []):
        environment = _environment(wave.get("environment", PROD))
        slot = by_id.get(str(wave.get("slot_id", "")).strip())
        reason = ""
        if slot is None:
            reason = f"unknown window '{wave.get('slot_id')}'"
        elif environment == PROD and slot.environment != PROD:
            reason = f"window {slot.id} is not a production window"
        elif not calendar.check(environment, slot.start, slot.end)[0]:
            reason = calendar.check(environment, slot.start, slot.end)[1]
        if reason:
            replacement = next_free(environment)
            if replacement is None:
                notes.append(f"Dropped wave '{wave.get('name')}': {reason} and no valid window is left.")
                continue
            notes.append(f"Moved wave '{wave.get('name')}' to {replacement.label}: {reason}.")
            slot = replacement
        used.add(slot.id)

        pool = remaining.get(environment, [])
        servers = [s for s in dict.fromkeys(wave.get("servers", [])) if s in pool]
        dropped = len(set(wave.get("servers", []))) - len(servers)
        if dropped:
            notes.append(f"Removed {dropped} server(s) from wave '{wave.get('name')}' that are not "
                         f"{environment.lower()} servers of this application or were already scheduled.")
        for server in servers:
            pool.remove(server)
        if not servers:
            continue
        waves.append({**wave, "environment": environment, "slot_id": slot.id, "servers": servers,
                      "start": slot.start, "end": slot.end, "window": slot.label, "window_kind": slot.kind,
                      "window_minutes": slot.minutes})

    for environment, leftover in remaining.items():
        if not leftover:
            continue
        last_end = max((w["end"] for w in waves if w["environment"] == environment), default=None)
        slot = next_free(environment, last_end) or next_free(environment)
        if slot is None:
            notes.append(f"{len(leftover)} {environment.lower()} server(s) could not be scheduled: no window left "
                         "in the planning horizon.")
            continue
        used.add(slot.id)
        notes.append(f"Added a wave for {len(leftover)} {environment.lower()} server(s) the plan left out.")
        waves.append({"name": f"{environment} — remaining servers", "environment": environment, "slot_id": slot.id,
                      "servers": leftover, "work_items": [], "estimated_minutes": 0, "downtime_expected": False,
                      "pre_checks": [], "post_checks": [], "rollback": "", "rationale": "Added by the schedule guardrail.",
                      "start": slot.start, "end": slot.end, "window": slot.label, "window_kind": slot.kind,
                      "window_minutes": slot.minutes})

    waves.sort(key=lambda w: w["start"])
    for wave in waves:  # final assertion: nothing leaves this function outside the policy
        allowed, why = calendar.check(wave["environment"], wave["start"], wave["end"])
        if not allowed:
            raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': {why}")
        if wave.get("estimated_minutes", 0) > wave["window_minutes"]:
            notes.append(f"Wave '{wave['name']}' is estimated at {wave['estimated_minutes']} min but its window is "
                         f"{wave['window_minutes']} min. Split it or reduce the servers.")

    dev_end = max((w["end"] for w in waves if w["environment"] == DEV), default=None)
    prod_start = min((w["start"] for w in waves if w["environment"] == PROD), default=None)
    if dev_end and prod_start and prod_start < dev_end:
        notes.append("Production starts before development has finished. Development should prove the fix first.")

    return {**plan, "waves": waves, "guardrail_notes": notes}
