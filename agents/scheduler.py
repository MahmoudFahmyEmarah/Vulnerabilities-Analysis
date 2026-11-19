"""Scheduling agent: refines a rule-based draft into a fix schedule.

The agent only chooses among change windows the calendar offers (by slot_id) and
decides sequencing, grouping and checks. It never writes dates or times itself;
guardrails/output_checks.enforce_schedule() rejects anything outside the policy.
"""
from __future__ import annotations

import json
from typing import Any

from agents.base_agent import BaseAgent, few_shot
from agents.schemas import SchedulePlan


class SchedulerAgent(BaseAgent):
    name = "scheduler"
    system_prompt = "scheduler.md"
    template = "schedule.md"
    schema = SchedulePlan

    def plan(self, context: dict[str, Any], slots: list[dict[str, Any]], draft: dict[str, Any],
             policy_summary: str) -> tuple[dict[str, Any], dict[str, Any]]:
        answer, details = self.run(
            context=json.dumps(context, indent=1, ensure_ascii=False, default=str),
            slots=json.dumps(slots, indent=1),
            draft=json.dumps(draft, indent=1, ensure_ascii=False, default=str),
            policy=policy_summary,
            example=few_shot("schedule"),
        )
        return answer.model_dump(), details
