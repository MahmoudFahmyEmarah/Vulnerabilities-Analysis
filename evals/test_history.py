"""Week-over-week tracking: comparison rules, trend totals, report dates. Small synthetic frames only."""
from __future__ import annotations

import os
import threading
import time
from datetime import date, datetime
from pathlib import Path

import pandas as pd

import settings
from tools import data_loader as dl, history


def vulns(rows: list[tuple]) -> pd.DataFrame:
    """rows: (device, application, qid, port, severity, qualys status, past sla)"""
    frame = pd.DataFrame(rows, columns=["Device Name", "Applications", "Qualys ID", "Port Number", "Severity",
                                        "Qualys Status", "Past SLA"])
    frame["SLA Status"] = frame.pop("Past SLA").map({True: "Breached", False: "Within SLA"})
    return frame.assign(Platform="P", Title="t", **{"Last Scan Date Time": pd.Timestamp("2026-11-01")})


def test_vulnerability_changes_and_application_deltas():
    previous = vulns([
        ("10.0.0.1", "App A", 100, "443", "High", "Active", True),      # still open (port read as text)
        ("10.0.0.1", "App A", 200, None, "Low", "Active", False),       # fixed: server still reported
        ("10.0.0.2", "App A", 300, None, "Low", "Active", True),        # fixed: server only in the CS report now
        ("10.0.0.3", "App B", 400, None, "Medium", "Active", True),     # not rescanned: server gone
    ])
    current = vulns([
        ("10.0.0.1", "App A", 100, 443.0, "High", "Active", True),
        ("10.0.0.1", "App A", 100, 443.0, "High", "Active", True),      # listed twice: counted once
        ("10.0.0.1", "App A", 500, None, "Critical", "Re-Opened", False),
        ("10.0.0.9", "App B", 600, None, "Low", "New", False),          # server new this week
    ])
    changes = history.vulnerability_changes(current, previous, current_servers={"10.0.0.1", "10.0.0.2", "10.0.0.9"})
    by_qid = changes.set_index("Qualys ID")["Change"].astype(str).to_dict()
    assert by_qid == {"100": "Still open", "500": "New", "600": "New", "200": "Fixed", "300": "Fixed",
                      "400": "Not rescanned"}
    assert set(changes.loc[changes["Qualys ID"].isin(["500", "600"]), "Change detail"]) == {"Re-opened",
                                                                                              "Server new this week"}

    table = history.application_deltas(current, previous, {"10.0.0.1", "10.0.0.2", "10.0.0.9"}).set_index("Applications")
    assert table.loc["App A", ["New", "Still open", "Fixed", "Not rescanned"]].tolist() == [1, 1, 2, 0]
    assert table.loc["App B", ["New", "Not rescanned", "Current total", "Previous total", "Net change"]].tolist() == [1, 1, 1, 1, 0]
    assert table.loc["App A", ["Re-opened", "Past SLA now", "Past SLA before", "Past SLA change"]].tolist() == [1, 1, 2, -1]
    # Without the full server list, the server whose findings all disappeared cannot be called fixed.
    blind = history.vulnerability_changes(current, previous)
    assert blind.set_index("Qualys ID").loc["300", "Change"] == history.NOT_RESCANNED


def test_mbss_and_cs_changes():
    base = {"Applications": "App A", "Platform": "P", "Criticality": "High"}
    previous = pd.DataFrame([{"Device Name": "s1", "Qualys Control ID": "1", **base},
                             {"Device Name": "s1", "Qualys Control ID": "2", **base},
                             {"Device Name": "s2", "Qualys Control ID": "1", **base}])
    current = pd.DataFrame([{"Device Name": "s1", "Qualys Control ID": "2", **base},
                            {"Device Name": "s1", "Qualys Control ID": "3", **base}])
    mbss = history.mbss_changes(current, previous, current_servers={"s1"})
    assert mbss.set_index(["Device Name", "Qualys Control ID"])["Change"].astype(str).to_dict() == {
        ("s1", "2"): "Still failing", ("s1", "3"): "Newly failing", ("s1", "1"): "Now passing",
        ("s2", "1"): "Not rescanned"}

    def cs(rows):  # (device, antivirus state, siem state)
        frame = pd.DataFrame(rows, columns=["Device Name", "Antivirus State", "SIEM State"])
        for control in dl.CS_CONTROLS:
            frame[f"{control} State"] = frame.get(f"{control} State", "Implemented")
            frame[dl.CS_CONTROLS[control][0]] = "x"
        return frame.assign(Applications="App A", Platform="P")

    before = cs([("s1", "Gap", "Implemented"), ("s2", "Partial", "Gap"), ("s3", "Gap", "Implemented")])
    now = cs([("s1", "Implemented", "Implemented"), ("s2", "Partial", "Implemented"), ("s4", "Gap", "Implemented")])
    changes = history.cs_changes(now, before)
    assert changes.set_index(["Device Name", "Control"])["Change"].astype(str).to_dict() == {
        ("s1", "Antivirus"): "Gap closed", ("s2", "Antivirus"): "Still a gap", ("s2", "SIEM"): "Gap closed",
        ("s3", "Antivirus"): "Not rescanned", ("s4", "Antivirus"): "New gap"}
    totals = history.count_changes(changes, by=()).iloc[0]
    assert (totals["Current total"], totals["Previous total"]) == (2, 4)


def test_weekly_trend_counts_missing_groups_as_zero_and_missing_files_as_blank():
    week1, week2 = history.week_start("2026-11-01 23:00"), history.week_start("2026-11-10")
    assert (week1, week2) == (pd.Timestamp("2026-11-01"), pd.Timestamp("2026-11-08"))  # Sundays
    sla = {"High": 14, "Low": 45}
    v1 = vulns([("a", "App A", 1, None, "High", "Active", True), ("b", "App B", 2, None, "Low", "Active", False)])
    v2 = vulns([("a", "App A", 1, None, "High", "Active", False)])
    m1 = pd.DataFrame([{"Device Name": "a", "Applications": "App A", "Platform": "P", "Qualys Control ID": "9",
                        "Criticality": "Critical"}])
    weeks = [(dl.VULN, week1, dl.summarise(dl.VULN, v1, sla)), (dl.VULN, week2, dl.summarise(dl.VULN, v2, sla)),
             (dl.MBSS, week1, dl.summarise(dl.MBSS, m1))]
    totals = history.weekly_trend(weeks).set_index("Week")
    assert totals["Open findings"].tolist() == [2, 1] and totals["Past SLA"].tolist() == [1, 0]
    assert totals.loc[week1, "MBSS failed"] == 1 and pd.isna(totals.loc[week2, "MBSS failed"])
    per_app = history.weekly_trend(weeks, by="Applications").set_index(["Week", "Applications"])
    assert per_app.loc[(week2, "App B"), "Open findings"] == 0


def test_files_are_ordered_by_report_date_and_extra_sheets_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_dir", lambda: tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    folder = tmp_path / "data"
    folder.mkdir()
    columns = {column: ["x"] for column in dl.REQUIRED[dl.VULN]}
    for name, scanned in (("Vulnerability week 45.xlsx", "2026-11-08 10:00"), ("Vulnerability week 44.xlsx", "2026-11-01 10:00")):
        report = pd.DataFrame({**columns, "Overall Status": ["Open"], "Ageing in Days": [3], "Severity": ["Low"],
                               "Qualys ID": [1], "Last Scan Date Time": [scanned]})
        with pd.ExcelWriter(folder / name) as writer:
            report.to_excel(writer, sheet_name="Data", index=False)
            pd.DataFrame({"Summary": [1]}).to_excel(writer, sheet_name="Pivot", index=False)
    # Last week's file arrives after this week's: by modification time it would look newest.
    os.utime(folder / "Vulnerability week 44.xlsx", (datetime(2026, 11, 20).timestamp(),) * 2)

    infos = dl.describe_files(folder)[dl.VULN]
    assert [info.path.name for info in infos] == ["Vulnerability week 45.xlsx", "Vulnerability week 44.xlsx"]
    assert infos[0].report_date == datetime(2026, 11, 8, 10) and infos[0].date_source == "Last Scan Date Time"
    assert infos[0].error is None and len(infos[0].skipped_sheets) == 1 and "Pivot" in infos[0].skipped_sheets[0]
    assert dl.load_summary(dl.VULN, infos[0].path)["Open findings"].sum() == 1


def test_two_weekly_reports_stay_apart_whatever_weekday_the_scans_ended():
    def info(kind: str, when: str) -> dl.FileInfo:
        return dl.FileInfo(Path(f"{kind}-{when}.xlsx"), kind, datetime.fromisoformat(when), "test")

    files = [info(dl.VULN, "2026-11-01T23:34"), info(dl.MBSS, "2026-11-01T00:00"), info(dl.CS, "2026-11-03T13:12"),
             # next week's scans end on Saturday: the same Sunday-to-Saturday calendar week as the first report
             info(dl.VULN, "2026-11-07T22:00"), info(dl.MBSS, "2026-11-07T00:00"), info(dl.CS, "2026-11-09T09:00")]
    sets = history.group_reports(files)
    assert [sorted(f.path.name for f in group.values()) for _, group in sets] == [
        ["cs_controls-2026-11-09T09:00.xlsx", "mbss-2026-11-07T00:00.xlsx", "vulnerabilities-2026-11-07T22:00.xlsx"],
        ["cs_controls-2026-11-03T13:12.xlsx", "mbss-2026-11-01T00:00.xlsx", "vulnerabilities-2026-11-01T23:34.xlsx"]]


def test_simultaneous_cache_writes_do_not_collide(tmp_path):
    target, errors = tmp_path / "cache.parquet", []

    def slow_write(path: Path) -> None:
        path.write_bytes(b"same content")
        time.sleep(0.2)

    def worker() -> None:
        try:
            dl._write_atomic(target, slow_write)
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and target.read_bytes() == b"same content"
    assert [p.name for p in tmp_path.iterdir()] == ["cache.parquet"]   # no temporary files left behind


def _workbook(path: Path, kind: str, **columns) -> Path:
    data = {column: ["x"] for column in dl.REQUIRED[kind]}
    if kind == dl.VULN:
        data.update({"Overall Status": ["Open"], "Ageing in Days": [3], "Severity": ["Low"], "Qualys ID": [1]})
    data.update({name: [value] for name, value in columns.items()})
    pd.DataFrame(data).to_excel(path, index=False)
    return path


def test_a_report_date_set_by_the_user_moves_the_file_until_another_file_replaces_it(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_dir", lambda: tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    folder = tmp_path / "data"
    folder.mkdir()
    _workbook(folder / "Vulnerability 11-16.xlsx", dl.VULN, **{"Last Scan Date Time": "2026-11-15 23:18"})
    cs = _workbook(folder / "CS Controls 11-16.xlsx", dl.CS)      # dated by when the workbook was saved: today
    assert len(history.group_reports([i for infos in dl.describe_files(folder).values() for i in infos])) == 2

    dl.set_report_date(cs, date(2026, 11, 15))
    info = dl.describe_files(folder)[dl.CS][0]
    assert (info.report_date, info.date_source) == (datetime(2026, 11, 15), dl.USER_DATE)
    assert info.found_date.date() > date(2026, 11, 15) and info.found_source == dl.FILE_DATE
    sets = history.group_reports([i for infos in dl.describe_files(folder).values() for i in infos])
    assert len(sets) == 1 and set(sets[0][1]) == {dl.VULN, dl.CS}

    _workbook(cs, dl.CS, Applications="a different, longer application name")   # same name, other file
    assert dl.describe_files(folder)[dl.CS][0].date_source == dl.FILE_DATE
    dl.set_report_date(cs, None)
    assert dl.chosen_dates(folder) == {}


def test_an_upload_is_checked_outside_the_data_folder_and_read_only_once(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_dir", lambda: tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    folder = tmp_path / "data"
    source = _workbook(tmp_path / "source.xlsx", dl.VULN, **{"Last Scan Date Time": "2026-11-15 23:18"})
    staged = dl.stage_upload("Vulnerability week 46.xlsx", source.read_bytes())
    assert dl.describe_files(folder)[dl.VULN] == []                 # the pages do not see it yet
    checked = dl.file_info(dl.VULN, staged)
    assert checked.report_date == datetime(2026, 11, 15, 23, 18) and checked.error is None

    def read_again(*args, **kwargs):
        raise AssertionError("the upload was read a second time")

    monkeypatch.setattr(dl, "_combine", read_again)
    target = dl.adopt_upload(staged, folder)
    assert dl.file_info(dl.VULN, target).report_date == checked.report_date
    assert len(dl.load_vulnerabilities(target)) == 1
    assert not staged.parent.exists() and [p.name for p in folder.iterdir()] == ["Vulnerability week 46.xlsx"]


def test_server_addresses_keep_their_last_octet_in_finding_keys():
    frame = vulns([("10.1.2.0", "App A", 101.0, 443.0, "High", "Active", False)])
    keys = dl.unique_findings(dl.VULN, frame)[["Device Name", "Qualys ID", "Port Number"]].iloc[0].tolist()
    assert keys == ["10.1.2.0", "101", "443"]
