"""Checks on what the model returns before an engineer sees it.

* review_recommendation: flags commands that are destructive or need a second look.
* enforce_schedule: rebuilds a model-proposed schedule so that it obeys the change-window
  policy no matter what the model wrote. Dates and times always come from calendar slots.
"""
from __future__ import annotations

import re
from datetime import timedelta
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


_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\s*(?:\([^)]*\)|\[[^\]]*\])")


def strip_images(value: Any) -> Any:
    """Remove Markdown images from model text (strings inside dicts and lists too); the alt text stays.

    Model answers are shown as Markdown, and an image there would be fetched by every viewer's browser,
    which is a way for instructions injected through scan text to send data to an outside host.
    """
    if isinstance(value, str):
        return _MD_IMAGE.sub(r"\1", value)
    if isinstance(value, list):
        return [strip_images(item) for item in value]
    if isinstance(value, dict):
        return {key: strip_images(item) for key, item in value.items()}
    return value


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


DEFAULT_SERVER_MINUTES = 60   # used for a server with no estimate


def _batches(servers: list[str], parallel: int) -> list[list[str]]:
    return [servers[index:index + parallel] for index in range(0, len(servers), parallel)]


def work_minutes(servers: list[str], minutes: dict[str, int], parallel: int) -> int:
    """Time to work through ``servers``, ``parallel`` at a time; a batch takes as long as its slowest server."""
    return sum(max(minutes.get(s, DEFAULT_SERVER_MINUTES) for s in batch)
               for batch in _batches(servers, max(1, parallel)))


def _fit(servers: list[str], minutes: dict[str, int], parallel: int, capacity: int) -> tuple[list[str], list[str]]:
    """Split ``servers`` into the batches that fit in ``capacity`` minutes, and the rest."""
    taken: list[str] = []
    used = 0
    for batch in _batches(servers, max(1, parallel)):
        need = max(minutes.get(s, DEFAULT_SERVER_MINUTES) for s in batch)
        if used + need > capacity:
            break
        taken += batch
        used += need
    return taken, servers[len(taken):]


def enforce_schedule(
    plan: dict[str, Any],
    slots: list[Slot],
    servers_by_env: dict[str, list[str]],
    calendar: SaudiCalendar,
    minutes: dict[str, int] | None = None,
    parallel: int = 1,
    soak_days: int = 0,
) -> dict[str, Any]:
    """Make a proposed plan obey the policy. Returns the corrected plan with 'guardrail_notes'.

    ``minutes`` is the estimated work per server (servers without one count DEFAULT_SERVER_MINUTES)
    and ``parallel`` how many servers are worked on at the same time.

    Rules applied:
      1. A wave's time comes from its slot; an unknown slot, a slot another wave already uses, or one
         too short for even one batch is replaced by the next free valid one.
      2. A production wave must sit in a production window that passes calendar.check().
      3. Only servers that belong to the application and to the wave's environment are kept;
         each server appears once.
      4. A wave holds only as much work as fits in its window. The estimate is computed here, not
         taken from the plan; servers that do not fit, and servers the plan forgot, are packed into
         further free windows.
      5. Development goes first: no production wave starts before the last development wave has
         ended plus ``soak_days``. Production waves that do are moved to a later window.
    """
    notes: list[str] = []
    by_id = {slot.id: slot for slot in slots}
    free = {env: [slot for slot in slots if slot.environment == env] for env in (PROD, DEV)}
    used: set[str] = set()
    remaining = {env: list(servers) for env, servers in servers_by_env.items()}
    minutes = dict(minutes or {})
    parallel = max(1, int(parallel))
    waves: list[dict[str, Any]] = []

    def first_batch_fits(servers: list[str], slot: Slot) -> bool:
        return work_minutes(servers[:parallel], minutes, parallel) <= slot.minutes

    def next_free(environment: str, servers: list[str], not_before=None) -> Slot | None:
        for slot in free.get(environment, []):
            if slot.id in used or (not_before is not None and slot.start < not_before):
                continue
            if first_batch_fits(servers, slot):
                return slot
        return None

    def place(wave: dict[str, Any], environment: str, slot: Slot, servers: list[str]) -> None:
        used.add(slot.id)
        waves.append({**wave, "environment": environment, "slot_id": slot.id, "servers": servers,
                      "estimated_minutes": work_minutes(servers, minutes, parallel),
                      "start": slot.start, "end": slot.end, "window": slot.label, "window_kind": slot.kind,
                      "window_minutes": slot.minutes})

    def schedule_wave(wave: dict[str, Any], environment: str, not_before) -> None:
        name = wave.get("name")
        pool = remaining.get(environment, [])
        servers = [s for s in dict.fromkeys(wave.get("servers", [])) if s in pool]
        dropped = len(set(wave.get("servers", []))) - len(servers)
        if dropped:
            notes.append(f"Removed {dropped} server(s) from wave '{name}' that are not "
                         f"{environment.lower()} servers of this application or were already scheduled.")
        if not servers:
            return

        slot = by_id.get(str(wave.get("slot_id", "")).strip())
        reason = ""
        if slot is None:
            reason = f"unknown window '{wave.get('slot_id')}'"
        elif slot.id in used:
            reason = f"window {slot.id} is already used by another wave"
        elif environment == PROD and slot.environment != PROD:
            reason = f"window {slot.id} is not a production window"
        elif not calendar.check(environment, slot.start, slot.end)[0]:
            reason = calendar.check(environment, slot.start, slot.end)[1]
        elif not_before is not None and slot.start < not_before:
            reason = (f"window {slot.id} starts before development has finished and had its "
                      f"{soak_days} day(s) of soak")
        elif not first_batch_fits(servers, slot):
            reason = f"window {slot.id} ({slot.minutes} min) is too short for even one batch of servers"
        if reason:
            replacement = next_free(environment, servers, not_before)
            if replacement is None:
                notes.append(f"Dropped wave '{name}': {reason} and no valid window is left.")
                return   # its servers stay unscheduled and are handled with the leftovers
            notes.append(f"Moved wave '{name}' to {replacement.label}: {reason}.")
            slot = replacement

        taken, rest = _fit(servers, minutes, parallel, slot.minutes)
        if rest:
            notes.append(f"Wave '{name}' needs about {work_minutes(servers, minutes, parallel)} min but its window "
                         f"is {slot.minutes} min: {len(rest)} server(s) moved to a later window.")
        for server in taken:
            pool.remove(server)
        place(wave, environment, slot, taken)

    def pack_leftovers(environment: str, not_before) -> None:
        leftover = remaining.get(environment, [])
        if not leftover:
            return
        queue = list(leftover)
        ends = [w["end"] for w in waves if w["environment"] == environment] + ([not_before] if not_before else [])
        after = max(ends, default=None)
        added = 0
        while queue:
            slot = next_free(environment, queue, after) or next_free(environment, queue, not_before)
            if slot is None:
                notes.append(f"{len(queue)} {environment.lower()} server(s) could not be scheduled: no window left "
                             "in the planning horizon" + (" after development and its soak." if not_before else "."))
                break
            taken, queue = _fit(queue, minutes, parallel, slot.minutes)
            added += 1
            place({"name": f"{environment} — remaining servers {added}", "work_items": [], "downtime_expected": False,
                   "pre_checks": [], "post_checks": [], "rollback": "", "rationale": "Added by the schedule guardrail."},
                  environment, slot, taken)
            after = slot.end
        if added:
            placed = len(leftover) - len(queue)
            notes.append(f"Added {added} wave(s) for {placed} {environment.lower()} server(s) that the plan left out "
                         "or that did not fit in their window.")

    # Development first, so its end is known; production only after it and the soak.
    proposed = [(wave, _environment(wave.get("environment", PROD))) for wave in plan.get("waves", [])]
    for wave, environment in proposed:
        if environment == DEV:
            schedule_wave(wave, DEV, None)
    pack_leftovers(DEV, None)
    dev_end = max((w["end"] for w in waves if w["environment"] == DEV), default=None)
    production_from = dev_end + timedelta(days=max(0, int(soak_days))) if dev_end else None
    for wave, environment in proposed:
        if environment == PROD:
            schedule_wave(wave, PROD, production_from)
    pack_leftovers(PROD, production_from)

    waves.sort(key=lambda w: w["start"])
    for wave in waves:  # final assertion: nothing leaves this function outside the policy
        allowed, why = calendar.check(wave["environment"], wave["start"], wave["end"])
        if not allowed:
            raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': {why}")
        if wave["estimated_minutes"] > wave["window_minutes"]:
            raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': {wave['estimated_minutes']} min "
                             f"of work does not fit its {wave['window_minutes']}-min window")
        if wave["environment"] == PROD and production_from and wave["start"] < production_from:
            raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': production starts before "
                             "development has finished and soaked")

    return {**plan, "waves": waves, "guardrail_notes": notes}
