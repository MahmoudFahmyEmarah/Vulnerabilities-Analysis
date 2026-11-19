"""What is allowed to reach the model.

* Only whitelisted fields are sent; names of people never are (policies.yaml: never_send).
* Scanner text is untrusted: HTML is stripped, length is capped, and it is wrapped in
  <scan_data> tags so the system prompt can tell the model to treat it as data.
* IP addresses can be masked (policies.yaml: llm_input.mask_ip_addresses).
"""
from __future__ import annotations

import html
import re
from typing import Any

import pandas as pd

_TAG = re.compile(r"<[^>]+>")
_BREAK = re.compile(r"<\s*br\s*/?\s*>", re.IGNORECASE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# check type -> {field name sent to the model: source column}
FIELDS = {
    "vulnerability": {
        "title": "Title", "severity": "Severity", "operating_system": "Operating System",
        "application": "Applications", "topic": "Topic", "cves": "Related CVEs",
        "description": "Description", "scanner_solution": "Solution", "scan_result": "Results",
    },
    "mbss": {
        "control": "Control Description", "criticality": "Criticality", "os_family": "OS Family",
        "application": "Applications", "rationale": "RATIONALE", "scanner_remediation": "Remediation",
        "expected_configuration": "Expected Configuration", "current_evidence": "Posture Evidence",
    },
    "cs_control": {
        "control": "Control", "application": "Applications", "status_breakdown": "Status Breakdown",
        "operating_systems": "Operating Systems", "servers_affected": "Servers Affected",
    },
}


def strip_html(value: Any) -> str:
    if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)):
        return ""
    text = _BREAK.sub("\n", str(value))
    text = html.unescape(_TAG.sub(" ", text))
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n", text).strip()


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + f" … [truncated, {len(text) - limit} more characters]"


def mask_ips(text: str, mapping: dict[str, str]) -> str:
    """Replace each IP with a stable alias (server-1, server-2 ...). ``mapping`` is filled in place."""
    def alias(match: re.Match) -> str:
        return mapping.setdefault(match.group(0), f"server-{len(mapping) + 1}")
    return _IP.sub(alias, text)


def unmask_ips(text: str, mapping: dict[str, str]) -> str:
    for ip, alias in sorted(mapping.items(), key=lambda item: -len(item[1])):
        text = re.sub(rf"\b{re.escape(alias)}\b", ip, text)
    return text


def finding_for_model(check_type: str, row: dict[str, Any], policies: dict[str, Any]) -> dict[str, str]:
    """Build the cleaned, whitelisted view of one finding that is sent to the model."""
    rules = policies.get("llm_input", {})
    limit = int(rules.get("max_field_chars", 1500))
    blocked = set(rules.get("never_send", []))
    cleaned: dict[str, str] = {}
    for field, column in FIELDS[check_type].items():
        if column in blocked or column not in row:
            continue
        text = truncate(strip_html(row[column]), limit)
        if text:
            cleaned[field] = text
    return cleaned


_WRAPPER_TAG = re.compile(r"(?:<|&lt;)\s*/?\s*scan_data\b[^>]*?(?:>|&gt;)", re.IGNORECASE)


def as_scan_data(fields: dict[str, str]) -> str:
    """Render the fields inside <scan_data> so instructions hidden in scan text stay inert.

    A scan_data tag inside the text itself (raw, or HTML-escaped and decoded by strip_html) is
    replaced, so scanner text can never close the block early and pose as instructions.
    """
    body = "\n".join(f"[{name}]\n{_WRAPPER_TAG.sub('[scan_data tag removed]', value)}\n"
                     for name, value in fields.items())
    return f"<scan_data>\n{body}</scan_data>"
