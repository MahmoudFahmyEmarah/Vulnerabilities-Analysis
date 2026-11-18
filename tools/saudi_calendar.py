"""Saudi working calendar and change windows.

All rules come from guardrails/policies.yaml. Times are in Asia/Riyadh.
Production may only be changed outside working hours (and not on holidays when
the freeze is on); development may be changed at any time.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import holidays as holidays_lib

from tools.environment import DEV, PROD

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MIN_SLOT_MINUTES = 60


def _parse_time(text: str) -> time:
    hours, minutes = str(text).split(":")
    return time(int(hours), int(minutes))


@dataclass(frozen=True)
class Slot:
    """A change window offered to the scheduler."""

    id: str
    environment: str
    kind: str
    start: datetime
    end: datetime

    @property
    def minutes(self) -> int:
        return int((self.end - self.start).total_seconds() // 60)

    @property
    def label(self) -> str:
        return f"{self.start:%a %d %b %H:%M} → {self.end:%a %d %b %H:%M}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.id,
            "environment": self.environment,
            "kind": self.kind,
            "start": self.start.isoformat(timespec="minutes"),
            "end": self.end.isoformat(timespec="minutes"),
            "minutes": self.minutes,
        }


class SaudiCalendar:
    def __init__(self, policies: dict[str, Any]):
        calendar = policies["calendar"]
        self.tz = ZoneInfo(calendar["timezone"])
        self.working_days = {WEEKDAYS.index(day) for day in calendar["working_days"]}
        self.work_start = _parse_time(calendar["working_hours"]["start"])
        self.work_end = _parse_time(calendar["working_hours"]["end"])

        holiday_cfg = calendar.get("holidays", {})
        self.country = holiday_cfg.get("country", "SA")
        self.freeze = bool(holiday_cfg.get("freeze_production", True))
        self._extra = {date.fromisoformat(str(d)) for d in holiday_cfg.get("extra_dates") or []}
        self._removed = {date.fromisoformat(str(d)) for d in holiday_cfg.get("remove_dates") or []}
        self._by_year: dict[int, dict[date, str]] = {}

        production = policies["production"]
        self.night_start = _parse_time(production["night_window"]["start"])
        self.night_end = _parse_time(production["night_window"]["end"])
        self.weekend_start = _parse_time(production["weekend_day_window"]["start"])
        self.weekend_end = _parse_time(production["weekend_day_window"]["end"])

        preferred = policies["development"]["preferred_window"]
        self.dev_start = _parse_time(preferred["start"])
        self.dev_end = _parse_time(preferred["end"])

    # ---- basic calendar facts -------------------------------------------------
    def now(self) -> datetime:
        return datetime.now(self.tz)

    def _at(self, day: date, clock: time) -> datetime:
        return datetime.combine(day, clock, tzinfo=self.tz)

    def _holidays(self, year: int) -> dict[date, str]:
        if year not in self._by_year:
            try:
                found = holidays_lib.country_holidays(self.country, years=year, language="en_US")
            except Exception:  # noqa: BLE001 - older holiday tables without translations
                found = holidays_lib.country_holidays(self.country, years=year)
            self._by_year[year] = {day: str(name) for day, name in found.items()}
        return self._by_year[year]

    def holiday_name(self, day: date) -> str | None:
        if day in self._removed:
            return None
        if day in self._extra:
            return "Change freeze (policy)"
        return self._holidays(day.year).get(day)

    def is_weekend(self, day: date) -> bool:
        return day.weekday() not in self.working_days

    def is_working_day(self, day: date) -> bool:
        return not self.is_weekend(day) and self.holiday_name(day) is None

    def upcoming_holidays(self, after: date, days: int) -> list[tuple[date, str]]:
        out = []
        for offset in range(days + 1):
            day = after + timedelta(days=offset)
            name = self.holiday_name(day)
            if name:
                out.append((day, name))
        return out

    # ---- the rule every production change must pass ----------------------------
    def overlaps_working_hours(self, start: datetime, end: datetime) -> bool:
        day = start.astimezone(self.tz).date()
        last = end.astimezone(self.tz).date()
        while day <= last:
            if self.is_working_day(day):
                work_start, work_end = self._at(day, self.work_start), self._at(day, self.work_end)
                if start < work_end and end > work_start:
                    return True
            day += timedelta(days=1)
        return False

    def holiday_in(self, start: datetime, end: datetime) -> str | None:
        day = start.astimezone(self.tz).date()
        last = end.astimezone(self.tz).date()
        while day <= last:
            name = self.holiday_name(day)
            if name:
                return f"{name} ({day:%d %b %Y})"
            day += timedelta(days=1)
        return None

    def check(self, environment: str, start: datetime, end: datetime) -> tuple[bool, str]:
        """Is a change in [start, end] allowed for this environment? Returns (allowed, reason)."""
        if end <= start:
            return False, "window ends before it starts"
        if environment != PROD:
            return True, "development may be changed at any time"
        if self.overlaps_working_hours(start, end):
            return False, (
                f"overlaps working hours ({self.work_start:%H:%M}–{self.work_end:%H:%M}, "
                f"{', '.join(WEEKDAYS[d][:3] for d in sorted(self.working_days))})"
            )
        if self.freeze:
            holiday = self.holiday_in(start, end)
            if holiday:
                return False, f"falls on a holiday freeze: {holiday}"
        return True, "outside working hours"

    # ---- windows offered to the scheduler --------------------------------------
    def _clip(self, start: datetime, end: datetime, after: datetime) -> tuple[datetime, datetime] | None:
        """Drop windows that are over; start ongoing ones at the next quarter hour."""
        if start < after:
            minutes = (after.minute // 15 + 1) * 15
            start = after.replace(minute=0, second=0, microsecond=0) + timedelta(minutes=minutes)
        if (end - start).total_seconds() < MIN_SLOT_MINUTES * 60:
            return None
        return start, end

    def production_slots(self, after: datetime, days: int) -> list[Slot]:
        after = after.astimezone(self.tz)
        slots: list[Slot] = []
        for offset in range(-1, days + 1):
            day = after.date() + timedelta(days=offset)
            candidates = []
            night_end_day = day + timedelta(days=1) if self.night_end <= self.night_start else day
            candidates.append(("N", "Night", self._at(day, self.night_start), self._at(night_end_day, self.night_end)))
            if self.is_weekend(day):
                candidates.append(
                    ("D", "Weekend day", self._at(day, self.weekend_start), self._at(day, self.weekend_end))
                )
            for suffix, kind, start, end in candidates:
                clipped = self._clip(start, end, after)
                if clipped and self.check(PROD, *clipped)[0]:
                    slots.append(Slot(f"P-{day:%Y%m%d}-{suffix}", PROD, kind, *clipped))
        return sorted(slots, key=lambda slot: slot.start)

    def development_slots(self, after: datetime, days: int) -> list[Slot]:
        after = after.astimezone(self.tz)
        slots: list[Slot] = []
        for offset in range(days + 1):
            day = after.date() + timedelta(days=offset)
            if not self.is_working_day(day):
                continue
            clipped = self._clip(self._at(day, self.dev_start), self._at(day, self.dev_end), after)
            if clipped:
                slots.append(Slot(f"D-{day:%Y%m%d}", DEV, "Development", *clipped))
        return slots
