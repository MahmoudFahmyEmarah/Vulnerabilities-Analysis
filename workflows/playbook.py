"""Ansible files from an AI recommendation or a fix schedule.

The dashboard never runs these. An engineer reviews them and runs them from the team's Ansible control
node, with their own credentials (none are written here):

* finding_bundle()     - playbook.yml + inventory.ini for one finding and the servers it affects
* schedule_inventory() - inventory.ini with one group per wave and per change window

Guardrails: commands output_checks flags as risky, and commands that still contain a placeholder such
as <package>, are not turned into tasks; they are listed in the playbook as comments. The play targets
the development group unless ``-e target=production`` is given, stops at the first failing host, and
its rollback tasks only run with ``--tags rollback``.
"""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
from typing import Any

import pandas as pd
import yaml

from guardrails.output_checks import command_problems
from tools.environment import DEV, PROD

_REBOOT = re.compile(r"^\s*(sudo\s+)?(reboot|shutdown\s+-r\s+now|systemctl\s+reboot|init\s+6|Restart-Computer(\s+-Force)?)\s*;?\s*$",
                     re.IGNORECASE)
_GROUP = re.compile(r"[^a-z0-9_]+")


def is_windows(*texts: Any) -> bool:
    return any("windows" in str(text).lower() for text in texts if text is not None and not pd.isna(text))


def group_name(name: str) -> str:
    return _GROUP.sub("_", str(name).lower()).strip("_") or "group"


def _quoted(command: str) -> str:
    """Ansible templates every string; keep Jinja-looking text in a command literal."""
    return "{% raw %}" + command + "{% endraw %}" if "{{" in command or "{%" in command else command


def _shell(command: str, windows: bool) -> tuple[str, Any]:
    if _REBOOT.match(command):
        return ("ansible.windows.win_reboot", {}) if windows else ("ansible.builtin.reboot", {"reboot_timeout": 1800})
    return ("ansible.windows.win_shell" if windows else "ansible.builtin.shell"), _quoted(command)


def _task(name: str, command: str, windows: bool, tags: list[str], check: bool = False) -> dict[str, Any]:
    module, args = _shell(command, windows)
    task: dict[str, Any] = {"name": name[:160], module: args, "tags": tags}
    if check:
        task["changed_when"] = False
    return task


def _servers_table(servers: pd.DataFrame | None) -> pd.DataFrame:
    if servers is None or servers.empty or "Device Name" not in servers:
        return pd.DataFrame(columns=["Device Name", "Environment", "Windows", "Host Name"])
    table = servers.drop_duplicates("Device Name").copy()
    os_text = (table.get("Operating System", pd.Series("", index=table.index)).astype("string").fillna("") + " "
               + table.get("OS Family", pd.Series("", index=table.index)).astype("string").fillna(""))
    table["Windows"] = os_text.str.lower().str.contains("windows")
    if "Environment" not in table:
        table["Environment"] = PROD
    if "Host Name" not in table:
        table["Host Name"] = ""
    return table[["Device Name", "Environment", "Windows", "Host Name"]]


def inventory(servers: pd.DataFrame | None, title: str = "") -> str:
    """INI inventory: development / production groups, and linux / windows groups for the connection type."""
    table = _servers_table(servers)
    lines = [f"# Inventory for: {title}" if title else "# Inventory",
             "# No credentials are stored here. Pass them when you run, for example:",
             "#   ansible-playbook -i inventory.ini playbook.yml -u <user> --ask-pass --ask-become-pass",
             ""]

    def host_line(row) -> str:
        name = str(row["Host Name"]).strip() if pd.notna(row["Host Name"]) else ""
        return f"{row['Device Name']}" + (f"    # {name}" if name and name.lower() != "nan" else "")

    for group, environment in (("development", DEV), ("production", PROD)):
        lines.append(f"[{group}]")
        lines += [host_line(row) for _, row in table[table["Environment"] == environment].iterrows()]
        lines.append("")
    for group, flag in (("linux", False), ("windows", True)):
        lines.append(f"[{group}]")
        lines += [str(host) for host in table.loc[table["Windows"] == flag, "Device Name"]]
        lines.append("")
    lines += ["[windows:vars]",
              "# Windows hosts are reached over WinRM (or set ansible_connection=ssh for OpenSSH on Windows).",
              "ansible_connection=winrm", "ansible_port=5986", "ansible_winrm_transport=ntlm", ""]
    return "\n".join(lines)


def finding_playbook(content: dict[str, Any], finding: dict[str, Any], servers: pd.DataFrame | None = None, *,
                     parallel: int = 5, model: str = "", now: datetime | None = None) -> tuple[str, list[str]]:
    """The recommendation as a playbook. Returns (YAML text, commands left out and why)."""
    table = _servers_table(servers)
    windows = bool(table["Windows"].mean() > 0.5) if len(table) else is_windows(
        finding.get("Operating System"), finding.get("OS Family"))
    title = str(finding.get("Title") or finding.get("Control Description") or finding.get("Control") or "Finding")
    left_out: list[str] = []
    tasks: list[dict[str, Any]] = []

    def add(name: str, command: str, tags: list[str], check: bool = False) -> None:
        problems = command_problems(command)
        if problems:
            left_out.append(f"{command}    <- {'; '.join(problems)}")
            return
        tasks.append(_task(name, command, windows, tags, check))

    for number, step in enumerate(content.get("steps", []), 1):
        for command in step.get("commands", []):
            add(f"Step {number} - {step.get('title', '')}: {command}", command, ["fix"])
    for number, command in enumerate(content.get("verification", []), 1):
        add(f"Verify {number}: {command}", command, ["fix", "verify"], check=True)
    for number, command in enumerate(content.get("rollback", []), 1):
        add(f"Roll back {number}: {command}", command, ["never", "rollback"])

    restart = content.get("restart_required", "none")
    play: dict[str, Any] = {
        "name": f"Fix: {title}"[:160],
        "hosts": "{{ target | default('development') }}",
        **({} if windows else {"become": True}),
        "gather_facts": False,
        "serial": 1 if restart in ("service", "host") else max(1, int(parallel)),
        "max_fail_percentage": 0,
        "tasks": tasks,
    }
    stamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M")
    pace = "one at a time" if play["serial"] == 1 else f"{play['serial']} at a time"
    header = [
        f"# Generated by the Security Posture Dashboard on {stamp}.",
        f"# Finding: {title}" + (f" (Qualys ID {finding['Qualys ID']})" if finding.get("Qualys ID") else ""),
        "# Source: AI recommendation" + (f" ({model})" if model else "") + ". Review every task before you run it.",
        f"# Restart: {restart}. Servers are worked {pace}; the play stops when a host fails.",
        "#",
        "# 1. Development first (the play targets the development group unless told otherwise):",
        "#      ansible-playbook -i inventory.ini playbook.yml",
        "#    --check only shows which hosts are reached: Ansible skips shell tasks in check mode.",
        "# 2. Verify, then production inside an approved change window:",
        "#      ansible-playbook -i inventory.ini playbook.yml -e target=production",
        "#    One wave of the fix schedule: -e target=wave_1 with the inventory from the Fix Schedule page.",
        "# 3. Roll back:  ansible-playbook -i inventory.ini playbook.yml --tags rollback -e target=<group>",
        "",
    ]
    body = yaml.safe_dump([play], sort_keys=False, allow_unicode=True, width=1000)
    footer = []
    if not tasks:
        footer.append("# The recommendation has no command that could be turned into a task.")
    if left_out:
        footer += ["", "# Left out on purpose. Replace the placeholder or review the risk, then add the task yourself:"]
        footer += [f"#   {line}" for line in left_out]
    return "\n".join(header) + body + ("\n".join(footer) + "\n" if footer else ""), left_out


def finding_bundle(content: dict[str, Any], finding: dict[str, Any], servers: pd.DataFrame | None = None, *,
                   parallel: int = 5, model: str = "") -> bytes:
    """A zip with playbook.yml and inventory.ini."""
    text, _ = finding_playbook(content, finding, servers, parallel=parallel, model=model)
    title = str(finding.get("Title") or finding.get("Control Description") or finding.get("Control") or "")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("playbook.yml", text)
        archive.writestr("inventory.ini", inventory(servers, title))
    return buffer.getvalue()


def schedule_inventory(plan: dict[str, Any], context: dict[str, Any] | None = None) -> str:
    """INI inventory for a fix schedule: development / production, one group per wave and per window."""
    lines = [f"# Fix schedule for {plan.get('application', '')}, generated {plan.get('generated_at', '')} "
             f"({'AI-refined' if plan.get('source') == 'ai' else 'rule-based draft'}).",
             "# Run one wave at a time:  ansible-playbook -i inventory.ini playbook.yml -e target=wave_1",
             "# No credentials are stored here.", ""]
    for group, environment in (("development", DEV), ("production", PROD)):
        lines.append(f"[{group}]")
        lines += [s for wave in plan["waves"] if wave["environment"] == environment for s in wave["servers"]]
        lines.append("")
    for number, wave in enumerate(plan["waves"], 1):
        lines.append(f"# {wave['name']} · {wave['environment']} · {wave['window']}")
        lines.append(f"[wave_{number}]")
        lines += list(wave["servers"])
        lines.append("")
        for index, window in enumerate(wave.get("windows", []), 1):
            if len(wave["windows"]) == 1:
                break
            lines.append(f"# {window['window']} ({window['window_kind']})")
            lines.append(f"[wave_{number}_window_{index}]")
            lines += list(window["servers"])
            lines.append("")
    return "\n".join(lines)
