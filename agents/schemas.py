"""Typed shapes the agents must return. Validation is lenient about small format slips
(a string where a list was expected) and strict about structure."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [line.strip(" -•\t") for line in value.splitlines() if line.strip(" -•\t")]
    if isinstance(value, (list, tuple)):
        return [str(item) if not isinstance(item, dict) else "; ".join(f"{k}: {v}" for k, v in item.items())
                for item in value if item not in (None, "")]
    return [str(value)]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return default


class Step(BaseModel):
    title: str
    detail: str = ""
    commands: list[str] = Field(default_factory=list)

    _commands = field_validator("commands", mode="before")(_as_list)


class Recommendation(BaseModel):
    summary: str
    root_cause: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[Step]
    verification: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)
    restart_required: Literal["none", "service", "host"] = "none"
    downtime_expected: bool = False
    estimated_minutes_per_server: int = 30
    caveats: list[str] = Field(default_factory=list)

    _lists = field_validator("prerequisites", "verification", "rollback", "caveats", mode="before")(_as_list)
    _minutes = field_validator("estimated_minutes_per_server", mode="before")(lambda value: _as_int(value, 30))

    @field_validator("restart_required", mode="before")
    @classmethod
    def _restart(cls, value: Any) -> str:
        text = str(value or "none").lower()
        if any(word in text for word in ("host", "reboot", "server", "node")):
            return "host"
        if any(word in text for word in ("service", "application", "process", "restart")):
            return "service"
        return "none"

    @field_validator("steps", mode="before")
    @classmethod
    def _steps(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [{"title": item} if isinstance(item, str) else item for item in value]
        return value


class Wave(BaseModel):
    name: str
    environment: str
    slot_id: str
    servers: list[str] = Field(default_factory=list)
    work_items: list[str] = Field(default_factory=list)
    estimated_minutes: int = 0
    downtime_expected: bool = False
    pre_checks: list[str] = Field(default_factory=list)
    post_checks: list[str] = Field(default_factory=list)
    rollback: str = ""
    rationale: str = ""

    _lists = field_validator("servers", "work_items", "pre_checks", "post_checks", mode="before")(_as_list)
    _minutes = field_validator("estimated_minutes", mode="before")(lambda value: _as_int(value, 0))

    @field_validator("rollback", "rationale", mode="before")
    @classmethod
    def _text(cls, value: Any) -> str:
        return " ".join(_as_list(value))


class SchedulePlan(BaseModel):
    summary: str
    risks: list[str] = Field(default_factory=list)
    waves: list[Wave]

    _risks = field_validator("risks", mode="before")(_as_list)


class TopicLabel(BaseModel):
    id: int
    topic: Literal["OS Issue", "Application Issue"]


class TopicLabels(BaseModel):
    labels: list[TopicLabel]
