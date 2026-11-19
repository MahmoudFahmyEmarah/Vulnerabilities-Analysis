"""Deterministic checks: classifier golden set, environment rules, Saudi calendar."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import pytest

import settings
from tools import classifier, environment, inventory
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
    assert classifier.os_family("Windows Server 2019 Standard 64 bit Edition Version 1809 Build 17763") == "Windows Server 2019"
    assert classifier.os_family("Red Hat Enterprise Linux 8.10") == "RHEL 8"


# ---- environment ----------------------------------------------------------------
@pytest.mark.parametrize("name, expected", [
    ("CEM Kafka Prod", PROD), ("KAFKA_NonProd", DEV), ("CMS NOKIA (NON-PROD)", DEV), ("APIM DR(Prod)", PROD),
    ("IoT_FPMS_DR_frontend", PROD), ("BigData_Dev", DEV), ("TeraData PreProd", DEV), ("Hadoop dev", DEV),
    ("KAFKA DR", PROD), ("CEM Kafka Pre-prod", DEV), ("KAFKA_NonProd(non prod)", DEV), ("NiFi_BDT_Non Prod", DEV),
    ("CAD Confluent Kafka-DEV", DEV), ("CAD Confluent Kafka-Test", DEV), ("SAS_VIYA_NonProd", DEV),
    ("NiFi_BDT_Prod", PROD), ("EDW_Teradata_Prod", PROD),
    ("R-Studio", None), ("Cache-DB", None), ("Trino Worker", None), ("Nifi_N", None),
])  # every name here is an application name from the latest reports
def test_environment_from_name(name, expected):
    assert environment.environment_from_name(name) == expected


def test_environment_priority_and_safe_default():
    devices = pd.DataFrame({"Device Name": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
                            "Applications": ["CEM Kafka Prod", "Cache-DB", "Cache-DB", "Nifi_N"]})
    servers = pd.DataFrame({"IP": ["2.2.2.2"], "Environment": ["Development"]})
    overrides = pd.DataFrame({"Device Name": ["1.1.1.1", None], "Applications": [None, "Nifi_N"],
                              "Environment": ["Development", "Development"]})
    result = environment.resolve_environments(devices, servers, overrides).set_index("Device Name")
    assert result.loc["1.1.1.1", "Environment"] == DEV          # override beats the application name
    assert result.loc["2.2.2.2", "Env Source"] == environment.SRC_SERVER_LIST
    assert result.loc["3.3.3.3", "Environment"] == PROD         # unknown is treated as production
    assert result.loc["3.3.3.3", "Env Source"] == environment.SRC_ASSUMED
    assert result.loc["4.4.4.4", "Environment"] == DEV          # override by application


def test_report_application_name_wins_over_the_older_server_list():
    devices = pd.DataFrame({"Device Name": ["5.5.5.5", "6.6.6.6", "7.7.7.7"],
                            "Applications": ["CEM Kafka Prod", "NiFi_BDT_Non Prod", "Cache-DB"]})
    servers = pd.DataFrame({"IP": ["5.5.5.5", "6.6.6.6", "7.7.7.7"],
                            "Environment": ["Development", "Production", "Development"]})
    result = environment.resolve_environments(devices, servers, environment.load_overrides(Path("missing.csv")))
    result = result.set_index("Device Name")
    assert result.loc["5.5.5.5", "Environment"] == PROD and result.loc["5.5.5.5", "Env Source"] == environment.SRC_APP_NAME
    assert result.loc["6.6.6.6", "Environment"] == DEV and result.loc["6.6.6.6", "Env Source"] == environment.SRC_APP_NAME
    # the name says nothing here, so the server list decides
    assert result.loc["7.7.7.7", "Environment"] == DEV and result.loc["7.7.7.7", "Env Source"] == environment.SRC_SERVER_LIST


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


def test_weekend_inside_an_eid_break_is_frozen(calendar):
    # Eid on Friday, the day off moved to Sunday: the holiday table skips the Saturday in between.
    for day in ("2026-05-30", "2027-03-13"):
        allowed, reason = calendar.check(PROD, at(calendar, f"{day}T08:00"), at(calendar, f"{day}T20:00"))
        assert not allowed and "holiday" in reason.lower(), day
    assert calendar.check(PROD, at(calendar, "2026-11-21T08:00"), at(calendar, "2026-11-21T20:00"))[0]  # normal Saturday


def test_weekend_is_friday_saturday(calendar):
    assert calendar.is_weekend(datetime(2026, 11, 20).date()) and calendar.is_weekend(datetime(2026, 11, 21).date())
    assert not calendar.is_weekend(datetime(2026, 11, 22).date())


# ---- AI Platforms Inventory ---------------------------------------------------------
@pytest.fixture()
def inventory_file(tmp_path):
    """A small workbook with the same kinds of layout as the real inventory (made-up servers)."""
    import openpyxl

    book = openpyxl.Workbook()
    lake = book.active
    lake.title = "Dev-Advance"
    lake.append(["SrNo", "Environment", "IP's", "Hostname/ServerName", "Server Role", "Status", "BD Cluster Name"])
    lake.append([None, "Dev", "10.9.0.1", "lake-dev-01", "Master", "In Use", "cluster02"])
    prod = book.create_sheet("SAS Viya - Prod")              # two tables, no environment column
    prod.append(["SR/NO", "Jupyter Server"])
    prod.append([None, "APP", "Hostname", "IP"])
    prod.append(["1", "JupyterHub", "sas-01", " 10.9.0.2 "])
    prod.append([None, "Viya Server"])
    prod.append([None, "APP", "Hostname", "IP"])
    prod.append(["1", "CAS Worker", "sas-01", "10.9.0.2"])
    prod.append([None, "Licences", "Start_date"])
    prod.append([None, "SECRET-LICENCE-KEY", "2025-01-01"])
    gpu = book.create_sheet("GPUs")                          # several IP-like columns
    gpu.append(["SR#", "GPUIP", "FOR", "Product Name", "iLO IP", "iLO Credentials", "Hostname", "App/Data IP", "Gateway IP"])
    gpu.append(["1", "10.9.0.3", "(DEV GPU)", "DGX", "10.8.0.3", "admin/secret", "GPUDEV01", "10.9.0.3", "10.9.0.254"])
    tool = book.create_sheet("DataIku")
    tool.append(["Hostname (OS)", "VM Name", "IP Address", "Role", "Environment"])
    tool.append(["eng-01", "eng-01", "10.9.0.4", "Designer", "Prod"])
    tool.append(["eng-02", "eng-02", "10.9.0.5", "N/A", "N/A"])
    path = tmp_path / "inventory.xlsx"
    book.save(path)
    return path


def test_inventory_reader_handles_every_layout(inventory_file):
    frame = inventory.load_inventory(inventory_file, {"Advance": "AI Data Lake"}).set_index("IP")
    assert list(frame.index) == ["10.9.0.1", "10.9.0.2", "10.9.0.3", "10.9.0.4", "10.9.0.5"]
    assert frame.loc["10.9.0.1", ["AI Platform", "Environment", "Cluster"]].tolist() == ["AI Data Lake", DEV, "cluster02"]
    assert frame.loc["10.9.0.2", "Environment"] == PROD                      # from the sheet name
    assert frame.loc["10.9.0.2", "Server Role"] == "JupyterHub, CAS Worker"  # listed twice, both roles kept
    assert frame.loc["10.9.0.3", ["Hostname", "Environment"]].tolist() == ["GPUDEV01", DEV]
    assert frame.loc["10.9.0.4", "Environment"] == PROD
    assert pd.isna(frame.loc["10.9.0.5", "Environment"]) and pd.isna(frame.loc["10.9.0.5", "Server Role"])


def test_inventory_reader_never_returns_secrets(inventory_file):
    text = inventory.load_inventory(inventory_file).to_csv()
    assert "SECRET" not in text and "admin/secret" not in text and "10.8.0.3" not in text


def test_inventory_environment_wins_over_report_name_and_server_list():
    devices = pd.DataFrame({"Device Name": ["10.9.0.1", "10.9.0.5", "10.9.0.9"],
                            "Applications": ["CEM Kafka Prod", "Cache-DB", "Cache-DB"]})
    servers = pd.DataFrame({"IP": ["10.9.0.1"], "Environment": ["Production"]})
    listed = pd.DataFrame({"IP": ["10.9.0.1", "10.9.0.5"], "Environment": [DEV, None]})
    result = environment.resolve_environments(devices, servers, environment.load_overrides(Path("missing.csv")),
                                              inventory=listed).set_index("Device Name")
    assert result.loc["10.9.0.1", ["Environment", "Env Source"]].tolist() == [DEV, environment.SRC_INVENTORY]
    assert result.loc["10.9.0.5", "Env Source"] == environment.SRC_ASSUMED   # inventory lists it without an environment
    assert result.loc["10.9.0.9", "Env Source"] == environment.SRC_ASSUMED


def test_mapping_an_application_only_changes_the_servers_it_lists():
    devices = pd.DataFrame({"Device Name": ["10.8.0.1", "10.8.0.2", "10.8.0.3"], "Applications": ["DataIku"] * 3})
    inventory_frame = pd.DataFrame({"IP": ["10.8.0.3"], "Environment": [PROD]})
    no_list = pd.DataFrame(columns=["IP", "Environment"])
    empty = pd.DataFrame(columns=environment.OVERRIDE_COLUMNS)
    before = environment.resolve_environments(devices, no_list, empty, PROD, inventory_frame)
    listed = sorted(before.loc[before["Env Source"] == environment.SRC_ASSUMED, "Device Name"])
    assert listed == ["10.8.0.1", "10.8.0.2"]

    overrides = environment.remap_applications(empty, {"DataIku": listed}, {"DataIku": DEV})
    after = environment.resolve_environments(devices, no_list, overrides, PROD, inventory_frame).set_index("Device Name")
    assert after.loc["10.8.0.3", "Environment"] == PROD          # placed by the inventory: not flipped
    assert (after.loc[listed, "Environment"] == DEV).all()
    assert environment.mapped_environment(overrides, "DataIku", listed) == DEV
    assert environment.remap_applications(overrides, {"DataIku": listed}, {"DataIku": None}).empty   # blank clears


def test_missing_inventory_file_switches_the_feature_off(tmp_path):
    assert inventory.load_inventory(tmp_path / "nope.xlsx").empty and inventory.load_inventory(None).empty
