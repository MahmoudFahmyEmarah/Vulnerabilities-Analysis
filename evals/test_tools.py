"""Deterministic checks: classifier golden set, environment rules, Saudi calendar."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

import settings
from tools import classifier, environment
from tools.environment import DEV, PROD
from tools.saudi_calendar import SaudiCalendar

GOLDEN = [json.loads(line) for line in (Path(__file__).parent / "golden_set.jsonl").read_text("utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def calendar() -> SaudiCalendar:
    return SaudiCalendar(settings.load_policies())


def at(calendar: SaudiCalendar, text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=calendar.tz)


# ---- classifier -----------------------------------------------------------------
@pytest.mark.parametrize("case", GOLDEN, ids=[case["title"][:50] for case in GOLDEN])
def test_classifier_golden_set(case):
    topic, rule = classifier.classify_title(case["title"])
    assert topic == case["topic"], f"matched rule: {rule}"


def test_manual_label_wins_over_rules():
    titles = pd.Series(["Apache CXF Multiple Vulnerabilities"])
    labelled = classifier.classify_titles(titles, {"Apache CXF Multiple Vulnerabilities": classifier.OS})
    assert labelled["Topic"].iloc[0] == classifier.OS


def test_os_family():
    assert classifier.os_family("Red Hat Enterprise Linux Server 7.9") == "RHEL 7"
    assert classifier.os_family("Windows Server 2019 Standard 64 bit Edition Version 1809") == "Windows Server 2019"


# ---- environment ----------------------------------------------------------------
@pytest.mark.parametrize("name, expected", [
    ("CEM Kafka Prod", PROD), ("KAFKA_NonProd", DEV), ("CMS NOKIA (NON-PROD)", DEV), ("APIM DR(Prod)", PROD),
    ("IoT_FPMS_DR_frontend", PROD), ("BigData_Dev", DEV), ("TeraData PreProd", DEV), ("Hadoop dev", DEV),
    ("R-Studio", None), ("GitLab", None),
])
def test_environment_from_name(name, expected):
    assert environment.environment_from_name(name) == expected


def test_environment_priority_and_safe_default():
    devices = pd.DataFrame({"Device Name": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
                            "Applications": ["Kafka Prod", "Mystery", "Mystery", "Nifi_N"]})
    servers = pd.DataFrame({"IP": ["2.2.2.2"], "Environment": ["Development"]})
    overrides = pd.DataFrame({"Device Name": ["1.1.1.1", None], "Applications": [None, "Nifi_N"],
                              "Environment": ["Development", "Development"]})
    result = environment.resolve_environments(devices, servers, overrides).set_index("Device Name")
    assert result.loc["1.1.1.1", "Environment"] == DEV          # override beats the application name
    assert result.loc["2.2.2.2", "Env Source"] == environment.SRC_SERVER_LIST
    assert result.loc["3.3.3.3", "Environment"] == PROD         # unknown is treated as production
    assert result.loc["3.3.3.3", "Env Source"] == environment.SRC_ASSUMED
    assert result.loc["4.4.4.4", "Environment"] == DEV          # override by application


def test_conflicting_sources_are_treated_as_production():
    devices = pd.DataFrame({"Device Name": ["5.5.5.5", "6.6.6.6"], "Applications": ["CEM Kafka Prod", "KAFKA_NonProd"]})
    servers = pd.DataFrame({"IP": ["5.5.5.5", "6.6.6.6"], "Environment": ["Development", "Production"]})
    result = environment.resolve_environments(devices, servers, environment.load_overrides(Path("missing.csv")))
    assert set(result["Environment"]) == {PROD}
    assert set(result["Env Source"]) == {environment.SRC_CONFLICT}


# ---- Saudi calendar -------------------------------------------------------------
def test_production_blocked_in_working_hours(calendar):
    # Sunday 22 Nov 2026 is a working day in Saudi Arabia.
    assert not calendar.check(PROD, at(calendar, "2026-11-22T10:00"), at(calendar, "2026-11-22T12:00"))[0]
    assert not calendar.check(PROD, at(calendar, "2026-11-22T16:00"), at(calendar, "2026-11-22T18:00"))[0]
    assert not calendar.check(PROD, at(calendar, "2026-11-22T04:00"), at(calendar, "2026-11-22T09:00"))[0]


def test_production_allowed_at_night_and_weekend(calendar):
    assert calendar.check(PROD, at(calendar, "2026-11-22T22:00"), at(calendar, "2026-11-23T05:00"))[0]
    assert calendar.check(PROD, at(calendar, "2026-11-20T10:00"), at(calendar, "2026-11-20T15:00"))[0]  # Friday
    assert calendar.check(PROD, at(calendar, "2026-11-21T10:00"), at(calendar, "2026-11-21T15:00"))[0]  # Saturday


def test_development_allowed_any_time(calendar):
    assert calendar.check(DEV, at(calendar, "2026-11-22T10:00"), at(calendar, "2026-11-22T12:00"))[0]


def test_production_frozen_on_national_day(calendar):
    allowed, reason = calendar.check(PROD, at(calendar, "2026-09-23T22:00"), at(calendar, "2026-09-24T05:00"))
    assert not allowed and "holiday" in reason.lower()


def test_offered_production_slots_all_pass_the_rule(calendar):
    start = at(calendar, "2026-09-18T09:00")   # range that includes National Day
    slots = calendar.production_slots(start, 14)
    assert slots
    for slot in slots:
        assert calendar.check(PROD, slot.start, slot.end)[0], slot.label
        assert not calendar.overlaps_working_hours(slot.start, slot.end)
    assert not any(slot.start.date().isoformat() == "2026-09-23" for slot in slots)


def test_weekend_is_friday_saturday(calendar):
    assert calendar.is_weekend(datetime(2026, 11, 20).date()) and calendar.is_weekend(datetime(2026, 11, 21).date())
    assert not calendar.is_weekend(datetime(2026, 11, 22).date())
