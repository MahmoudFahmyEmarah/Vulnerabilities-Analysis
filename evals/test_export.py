"""Excel export: sheet layout, per-application totals and the rows written by the fast path."""
from __future__ import annotations

from datetime import datetime
from io import BytesIO

import openpyxl
import pandas as pd
import pytest

from tools.classifier import APP, OS
from tools.data_loader import CS_CONTROLS
from tools.environment import DEV, PROD, SRC_ASSUMED
from workflows import export


@pytest.fixture(scope="module")
def frames() -> dict[str, pd.DataFrame]:
    devices = pd.DataFrame({
        "Device Name": ["srv-a1", "srv-a2", "srv-b1", "srv-c1"],
        "Applications": ["Alpha", "Alpha", "Beta", "Gamma"],
        "Platform": ["Data", "Data", "Data", "Network"],
        "Environment": [PROD, DEV, PROD, PROD],
        "Env Source": ["Application name", "Server list", SRC_ASSUMED, SRC_ASSUMED],
    })
    place = devices.drop(columns="Applications")
    vulns = pd.DataFrame({
        "Applications": ["Alpha", "Alpha", "Alpha", "Beta", "Beta"],
        "Device Name": ["srv-a1", "srv-a1", "srv-a2", "srv-b1", "srv-b1"],
        "Severity": ["High", "Low", "Medium", "Critical", "Low"],
        "SLA Status": ["Breached", "Within SLA", "Due soon", "Breached", "Breached"],
        "Topic": [OS, APP, OS, OS, APP],
        "Title": ["=1+1", "A & B <c>", "Kernel update", "OpenSSL", "Java runtime"],
        "Ageing in Days": [40, 2, 28, 10, 99],
        "Date First Found": pd.to_datetime(["2026-01-05 10:30", None, "2026-02-01 08:00", "2026-03-01 08:00",
                                            "2026-04-01 08:00"]),
        "Application Delegate": ["Staff name"] * 5,
    }).merge(place, on="Device Name")
    mbss = pd.DataFrame({
        "Applications": ["Alpha", "Alpha", "Gamma", "Gamma"],
        "Device Name": ["srv-a1", "srv-a2", "srv-c1", "srv-c1"],
        "Criticality": ["Critical", "High", "Low", "Critical"],
        "Control Description": ["Password length", "SSH root login", "NTP", "Audit log"],
        "Section Manager": ["Staff name"] * 4,
    }).merge(place, on="Device Name")
    states = {"srv-a1": {}, "srv-a2": {"Antivirus": "Gap", "EDR": "Partial"}, "srv-b1": {"SIEM": "Gap"},
              "srv-c1": {"PAM": "Exception"}}
    cs = devices[["Device Name", "Applications"]].copy()
    for control in CS_CONTROLS:
        cs[f"{control} State"] = [states[name].get(control, "Implemented") for name in cs["Device Name"]]
    cs["Gaps"] = cs[[f"{c} State" for c in CS_CONTROLS]].isin(["Gap", "Partial"]).sum(axis=1)
    cs["Department Director"] = "Staff name"
    cs = cs.merge(place, on="Device Name")
    return {"vulns": vulns, "mbss": mbss, "cs": cs, "devices": devices}


@pytest.fixture(scope="module")
def workbook(frames) -> openpyxl.Workbook:
    blob = export.build_workbook(**frames, scope="All platforms", due_soon_days=3)
    return openpyxl.load_workbook(BytesIO(blob))


def _table(ws) -> pd.DataFrame:
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])


def test_sheets_charts_and_application_totals(frames, workbook):
    vulns, mbss, cs, devices = frames["vulns"], frames["mbss"], frames["cs"], frames["devices"]
    assert workbook.sheetnames == export.SHEETS
    assert len(workbook[export.SUMMARY]._charts) == 4
    assert len(workbook[export.TOP]._charts) == 3

    apps = _table(workbook[export.APPLICATIONS])
    assert sorted(apps["Application"]) == ["Alpha", "Beta", "Gamma"]
    expected = {
        "Servers": len(devices), "Production": int((devices["Environment"] == PROD).sum()),
        "Development": int((devices["Environment"] == DEV).sum()),
        "Environment unconfirmed": int((devices["Env Source"] == SRC_ASSUMED).sum()),
        "Open findings": len(vulns), "Past SLA": int((vulns["SLA Status"] == "Breached").sum()),
        "Due soon": int((vulns["SLA Status"] == "Due soon").sum()),
        "OS issues": int((vulns["Topic"] == OS).sum()), "Application issues": int((vulns["Topic"] == APP).sum()),
        "MBSS failed checks": len(mbss), "MBSS Critical": int((mbss["Criticality"] == "Critical").sum()),
        "Servers in the CS report": len(cs), "Servers with a CS gap": int((cs["Gaps"] > 0).sum()),
        **{severity: int((vulns["Severity"] == severity).sum()) for severity in export.SEVERITIES},
        **{f"{c} gaps": int(cs[f"{c} State"].isin(["Gap", "Partial"]).sum()) for c in CS_CONTROLS},
    }
    assert {column: int(apps[column].sum()) for column in expected} == expected
    assert apps["Past SLA"].tolist() == sorted(apps["Past SLA"], reverse=True)   # most past SLA first


def test_detail_rows_are_complete_safe_and_without_staff_names(frames, workbook):
    sheets = {name: _table(workbook[name]) for name in (export.VULNS, export.MBSS, export.CS)}
    assert [len(table) for table in sheets.values()] == [len(frames["vulns"]), len(frames["mbss"]),
                                                         int((frames["cs"]["Gaps"] > 0).sum())]
    for table in sheets.values():
        assert not set(export.STAFF_COLUMNS) & set(table.columns)

    vulns = sheets[export.VULNS]
    assert vulns["SLA Status"].tolist()[:3] == ["Breached"] * 3
    assert set(vulns["Title"]) == set(frames["vulns"]["Title"])     # "&" and "<" survive the XML
    formula_like = next(row for row in workbook[export.VULNS].iter_rows(min_row=2) if row[vulns.columns.get_loc(
        "Title")].value == "=1+1")
    assert formula_like[vulns.columns.get_loc("Title")].data_type == "s"   # text, never a formula
    first_found = dict(zip(vulns["Title"], vulns["Date First Found"]))
    assert first_found["=1+1"] == datetime(2026, 1, 5, 10, 30)
    assert pd.isna(first_found["A & B <c>"])   # blank date stays blank
    assert sheets[export.CS]["Controls with a gap"].tolist() == ["Antivirus, EDR", "SIEM"]


def test_email_carries_the_numbers_and_the_workbook_but_no_staff_or_server_names(frames):
    from email import message_from_bytes, policy

    from workflows import email_report

    blob = export.build_workbook(**frames, scope="Alpha and Beta")
    message = email_report.build_message(frames["vulns"], frames["mbss"], frames["cs"], frames["devices"],
                                         to=["team@example.com"], subject="Posture", scope="Alpha and Beta",
                                         attachment=blob, attachment_name="posture.xlsx",
                                         generated_at=datetime(2026, 11, 24, 9, 0))
    parsed = message_from_bytes(message.as_bytes(), policy=policy.default)
    attachments = list(parsed.iter_attachments())
    assert [part.get_filename() for part in attachments] == ["posture.xlsx"]
    assert openpyxl.load_workbook(BytesIO(attachments[0].get_content())).sheetnames == export.SHEETS
    html = parsed.get_body(("html",)).get_content()
    for body in (parsed.get_body(("plain",)).get_content(), html):
        assert "Staff name" not in body and "srv-" not in body
        assert "Kernel update" in body and "Password length" in body and "Beta" in body
    assert "A &amp; B &lt;c&gt;" in html
