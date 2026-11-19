"""Remediation agent: turns one finding into step-by-step fix instructions."""
from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent, few_shot
from agents.schemas import Recommendation
from guardrails.input_checks import as_scan_data

_TEMPLATES = {
    "vulnerability": "remediation_vulnerability.md",
    "mbss": "remediation_mbss.md",
    "cs_control": "remediation_cs_control.md",
}


class RemediationAgent(BaseAgent):
    name = "remediation"
    system_prompt = "remediation.md"
    schema = Recommendation

    def recommend(self, check_type: str, fields: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
        answer, details = self.run(
            template=_TEMPLATES[check_type],
            scan_data=as_scan_data(fields),
            example=few_shot("remediation"),
        )
        return answer.model_dump(), details
