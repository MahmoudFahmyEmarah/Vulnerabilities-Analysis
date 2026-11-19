"""Recommendation workflow: clean input -> knowledge base -> model -> output review -> store.

The model is called at most once per unique finding per OS; later requests are served
from the knowledge base unless the engineer disliked the answer or asks to regenerate.
"""
from __future__ import annotations

import json
from typing import Any

import settings
from agents.remediation import RemediationAgent
from guardrails import input_checks, output_checks
from memory.knowledge_base import KnowledgeBase
from tools import classifier

VULNERABILITY = "vulnerability"
MBSS = "mbss"
CS_CONTROL = "cs_control"


def finding_key(check_type: str, row: dict[str, Any]) -> tuple[str, str]:
    """(key, OS family) that identifies 'the same finding' for reuse."""
    if check_type == VULNERABILITY:
        return str(row["Title"]).strip(), classifier.os_family(row.get("Operating System"))
    if check_type == MBSS:
        return f"{row.get('Qualys Control ID', '')}: {str(row['Control Description']).strip()}"[:400], str(row.get("OS Family", ""))
    return str(row["Control"]).strip(), ""


def _result(record: dict[str, Any], source: str, seconds: float | None = None) -> dict[str, Any]:
    content = output_checks.strip_images(record["content"])   # also cleans answers stored before the check
    return {
        "id": record["id"],
        "content": content,
        "warnings": output_checks.review_recommendation(content),
        "source": source,
        "model": record.get("model", ""),
        "feedback": record.get("feedback"),
        "created_at": record.get("created_at", ""),
        "seconds": seconds,
    }


def cached_recommendation(check_type: str, row: dict[str, Any], kb: KnowledgeBase | None = None) -> dict[str, Any] | None:
    """Return the stored answer for this finding, if there is a reusable one. Never calls the model."""
    kb = kb or KnowledgeBase()
    key, os_name = finding_key(check_type, row)
    record = kb.find_recommendation(check_type, key, os_name) or (
        kb.find_recommendation(check_type, key, "") if os_name else None)  # legacy imports have no OS
    return _result(record, "knowledge base") if record else None


def get_recommendation(check_type: str, row: dict[str, Any], force: bool = False,
                       kb: KnowledgeBase | None = None) -> dict[str, Any]:
    """Return a recommendation for one finding, from the knowledge base or freshly generated."""
    kb = kb or KnowledgeBase()
    if not force:
        cached = cached_recommendation(check_type, row, kb)
        if cached:
            return cached

    policies = settings.load_policies()
    fields = input_checks.finding_for_model(check_type, row, policies)
    aliases: dict[str, str] = {}
    if policies.get("llm_input", {}).get("mask_ip_addresses"):
        fields = {name: input_checks.mask_ips(value, aliases) for name, value in fields.items()}

    content, details = RemediationAgent().recommend(check_type, fields)
    if aliases:
        content = json.loads(input_checks.unmask_ips(json.dumps(content, ensure_ascii=False), aliases))
    content = output_checks.strip_images(content)

    key, os_name = finding_key(check_type, row)
    record_id = kb.save_recommendation(check_type, key, os_name, str(row.get("Applications", "")), content,
                                       details["model"])
    record = {"id": record_id, "content": content, "model": details["model"], "feedback": None}
    return _result(record, "model", details.get("seconds"))
