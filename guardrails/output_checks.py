"""Checks on what the model returns before an engineer sees it.

* review_recommendation: flags commands that are destructive or need a second look.
* command_problems: why a command must not be run as it is (Ansible export, Run on servers).
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


_PLACEHOLDER = re.compile(r"<[A-Za-z][\w.:/=-]*>")


def command_problems(command: str) -> list[str]:
    """Why a command must not be run as it is (empty = fine to run after review).

    Used before a command is turned into an Ansible task or run on a server: a risky pattern is never
    run from the dashboard, and a placeholder such as <package> must be filled in first.
    """
    problems = [meaning for pattern, meaning in _RISKY_COMMANDS if re.search(pattern, command, re.IGNORECASE)]
    if _PLACEHOLDER.search(command):
        problems.append("still has a placeholder such as <package> to fill in")
    return problems


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


MAX_WAVES = 4   # waves in one plan, all environments together: each wave is one change to approve and run


def wave_limits(requested: dict[str, int] | None, servers_by_env: dict[str, list[str]],
                max_total: int = MAX_WAVES) -> dict[str, int]:
    """How many waves each environment may have.

    An environment with servers gets at least one wave and at most one per server; together they stay
    within ``max_total``. ``requested`` None (or an environment missing from it) means as many as allowed.
    """
    max_total = max(1, int(max_total))
    limits: dict[str, int] = {}
    for environment in (DEV, PROD):
        count = len(servers_by_env.get(environment, []))
        wanted = int((requested or {}).get(environment, max_total))
        limits[environment] = max(1, min(wanted, count, max_total)) if count else 0
    while sum(limits.values()) > max_total:
        larger = [e for e in (DEV, PROD) if limits[e] > 1]
        if not larger:
            break
        trim = max(larger, key=lambda e: (limits[e], e == DEV))   # trim the environment with more waves
        limits[trim] -= 1
    return limits


def enforce_schedule(
    plan: dict[str, Any],
    slots: list[Slot],
    servers_by_env: dict[str, list[str]],
    calendar: SaudiCalendar,
    minutes: dict[str, int] | None = None,
    parallel: int = 1,
    soak_days: int = 0,
    waves_per_env: dict[str, int] | None = None,
    max_waves: int = MAX_WAVES,
) -> dict[str, Any]:
    """Make a proposed plan obey the policy. Returns the corrected plan with 'guardrail_notes'.

    A wave is a group of servers changed together. It starts in the window its ``slot_id`` names and,
    when its servers do not fit, continues in the next free windows of its environment; each wave in
    the result lists them under "windows". ``minutes`` is the estimated work per server (servers
    without one count DEFAULT_SERVER_MINUTES) and ``parallel`` how many servers are worked on at once.

    Rules applied:
      1. Only servers that belong to the application and to the wave's environment are kept; each
         server is in one wave. Servers the plan left out join the last wave of their environment.
      2. At most ``waves_per_env`` waves per environment (see wave_limits) and ``max_waves`` in all;
         extra waves are merged into the last one kept.
      3. A wave's first window comes from its slot; an unknown slot, a slot already used, one too
         short for even one batch, or one that starts too early is replaced by the next free valid one.
         A wave without a slot_id simply gets the next free window.
      4. A production window must pass calendar.check(). Each window holds only as much work as fits
         in it; the estimate is computed here, not taken from the plan.
      5. Development goes first: no production window starts before the last development window has
         ended plus ``soak_days``. Within an environment, each wave starts after the previous one ends.
    """
    notes: list[str] = []
    by_id = {slot.id: slot for slot in slots}
    free = {env: [slot for slot in slots if slot.environment == env] for env in (PROD, DEV)}
    used: set[str] = set()
    minutes = dict(minutes or {})
    parallel = max(1, int(parallel))
    limits = wave_limits(waves_per_env, servers_by_env, max_waves)

    def first_batch_fits(servers: list[str], slot: Slot) -> bool:
        return work_minutes(servers[:parallel], minutes, parallel) <= slot.minutes

    def next_free(environment: str, servers: list[str], not_before) -> Slot | None:
        for slot in free.get(environment, []):
            if slot.id in used or (not_before is not None and slot.start < not_before):
                continue
            if first_batch_fits(servers, slot):
                return slot
        return None

    # 1-2. Which servers go in which wave.
    proposed: dict[str, list[dict[str, Any]]] = {DEV: [], PROD: []}
    for wave in plan.get("waves", []):
        proposed[_environment(wave.get("environment", PROD))].append(wave)
    assigned: dict[str, list[tuple[dict[str, Any], list[str]]]] = {}
    for environment in (DEV, PROD):
        pool = [str(s) for s in servers_by_env.get(environment, [])]
        members, taken = set(pool), set()
        kept: list[tuple[dict[str, Any], list[str]]] = []
        for wave in proposed[environment]:
            listed = list(dict.fromkeys(str(s) for s in wave.get("servers", [])))
            servers = [s for s in listed if s in members and s not in taken]
            if len(listed) > len(servers):
                notes.append(f"Removed {len(listed) - len(servers)} server(s) from wave '{wave.get('name')}' that are "
                             f"not {environment.lower()} servers of this application or were already in another wave.")
            if servers:
                taken.update(servers)
                kept.append((wave, servers))
        limit = limits[environment]
        if len(kept) > limit:
            extra, kept = kept[limit:], kept[:limit]
            for _, servers in extra:
                kept[-1][1].extend(servers)
            notes.append(f"Merged {len(extra)} {environment.lower()} wave(s) into '{kept[-1][0].get('name')}': "
                         f"at most {limit} {environment.lower()} wave(s) are allowed.")
        elif waves_per_env and kept and len(kept) < limit:
            notes.append(f"The plan has {len(kept)} {environment.lower()} wave(s); {limit} were asked for.")
        left = [s for s in pool if s not in taken]
        if left and kept:
            kept[-1][1].extend(left)
            notes.append(f"Added {len(left)} {environment.lower()} server(s) that the plan left out to wave "
                         f"'{kept[-1][0].get('name')}'.")
        elif left:
            kept.append(({"name": environment, "work_items": [], "downtime_expected": False, "pre_checks": [],
                          "post_checks": [], "rollback": "",
                          "rationale": "Added by the schedule guardrail: the plan had no wave for these servers."}, left))
            if proposed[environment]:
                notes.append(f"Added a {environment.lower()} wave for {len(left)} server(s) that the plan left out.")
        assigned[environment] = kept

    # 3-5. Windows for each wave, development first.
    waves: list[dict[str, Any]] = []

    def check_slot(slot_id: str, environment: str, servers: list[str], not_before, too_early: str):
        slot = by_id.get(slot_id)
        if slot is None:
            return None, f"unknown window '{slot_id}'"
        if slot.id in used:
            return None, f"window {slot.id} is already used by another wave"
        if environment == PROD and slot.environment != PROD:
            return None, f"window {slot.id} is not a production window"
        allowed, why = calendar.check(environment, slot.start, slot.end)
        if not allowed:
            return None, why
        if not_before is not None and slot.start < not_before:
            return None, f"window {slot.id} starts {too_early}"
        if not first_batch_fits(servers, slot):
            return None, f"window {slot.id} ({slot.minutes} min) is too short for even one batch of servers"
        return slot, ""

    def place(environment: str, not_before):
        """Place the environment's waves one after the other; returns when the last one ends."""
        end = None
        for wave, servers in assigned[environment]:
            name = wave.get("name") or environment
            after = end or not_before
            too_early = ("before the previous wave has finished" if end else
                         f"before development has finished and had its {soak_days} day(s) of soak")
            requested = str(wave.get("slot_id") or "").strip()
            slot, reason = check_slot(requested, environment, servers, after, too_early) if requested else (None, "")
            if slot is None:
                slot = next_free(environment, servers, after)
                if slot is None:
                    notes.append(f"Wave '{name}' ({len(servers)} server(s)) could not be scheduled: "
                                 + (f"{reason}, and " if reason else "") + "no window is left in the planning horizon.")
                    continue
                if reason:
                    notes.append(f"Moved wave '{name}' to {slot.label}: {reason}.")
            windows: list[dict[str, Any]] = []
            queue = list(servers)
            while queue:
                taken, queue = _fit(queue, minutes, parallel, slot.minutes)
                used.add(slot.id)
                windows.append({"slot_id": slot.id, "start": slot.start, "end": slot.end, "window": slot.label,
                                "window_kind": slot.kind, "window_minutes": slot.minutes, "servers": taken,
                                "estimated_minutes": work_minutes(taken, minutes, parallel)})
                if queue:
                    following = next_free(environment, queue, slot.end)
                    if following is None:
                        notes.append(f"{len(queue)} server(s) of wave '{name}' could not be scheduled: no window is "
                                     "left in the planning horizon.")
                        break
                    slot = following
            first, last = windows[0], windows[-1]
            waves.append({
                **{key: value for key, value in wave.items() if key != "window_minutes"},
                "name": name, "environment": environment, "slot_id": first["slot_id"],
                "servers": [s for window in windows for s in window["servers"]], "windows": windows,
                "start": first["start"], "end": last["end"],
                "window": first["window"] if len(windows) == 1 else
                f"{len(windows)} windows, {first['start']:%a %d %b} → {last['end']:%a %d %b}",
                "window_kind": " + ".join(dict.fromkeys(window["window_kind"] for window in windows)),
                "estimated_minutes": sum(window["estimated_minutes"] for window in windows)})
            end = last["end"]
        return end

    dev_end = place(DEV, None)
    production_from = dev_end + timedelta(days=max(0, int(soak_days))) if dev_end else None
    place(PROD, production_from)

    waves.sort(key=lambda w: w["start"])
    if len(waves) > max(1, int(max_waves)):  # final assertions: nothing leaves this function outside the policy
        raise ValueError(f"Schedule guardrail failed: {len(waves)} waves, at most {max_waves} are allowed")
    seen: set[str] = set()
    for wave in waves:
        for window in wave["windows"]:
            allowed, why = calendar.check(wave["environment"], window["start"], window["end"])
            if not allowed:
                raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': {why}")
            if window["estimated_minutes"] > window["window_minutes"]:
                raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': {window['estimated_minutes']} "
                                 f"min of work does not fit its {window['window_minutes']}-min window")
            if wave["environment"] == PROD and production_from and window["start"] < production_from:
                raise ValueError(f"Schedule guardrail failed for wave '{wave['name']}': production starts before "
                                 "development has finished and soaked")
            if window["slot_id"] in seen:
                raise ValueError(f"Schedule guardrail failed: window {window['slot_id']} is used twice")
            seen.add(window["slot_id"])

    return {**plan, "waves": waves, "guardrail_notes": notes}
