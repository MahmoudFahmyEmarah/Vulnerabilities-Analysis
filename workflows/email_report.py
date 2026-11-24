"""Email the insights for chosen applications: the numbers, the main findings, and the Excel workbook.

Pure functions, no Streamlit. The page (ui/views/email_report.py) picks the applications, filters the
frames to them and calls ``build_message``; ``send`` hands the message to the SMTP relay.

What leaves the app in the email body: counts, finding titles and control names. No server address,
host name or staff name is written in the body (the staff-name columns of policies.yaml
``llm_input.never_send`` are dropped before anything is read). The attached workbook is the same file
as the Overview page's Excel export, which also leaves staff names out by default.

SMTP settings come from .env or the process environment (for example the CML Application's
environment variables). A value set in .env wins; a blank one falls back to the environment.
"""
from __future__ import annotations

import html
import os
import re
import smtplib
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import numpy as np
import pandas as pd
from dotenv import dotenv_values

import settings
from tools import classifier, environment as env
from tools.data_loader import CS_CONTROLS
from workflows import export

XLSX = ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet")
SEVERITY_RANK = {name: index for index, name in enumerate(export.SEVERITIES)}
GAP_STATES = export.GAP_STATES

# Dashboard palette (ui/theme.py), written inline because mail clients drop <style> blocks.
_PURPLE, _PURPLE_DARK, _INK, _MUTED, _LINE, _SOFT, _RED = (
    "#4F008C", "#2A0A52", "#1D1033", "#6F6781", "#E8E1F3", "#F6F2FC", "#D03B3B")
_FONT = 'font-family:"Segoe UI",Arial,sans-serif;'

APP_TABLE_COLUMNS = ["Application", "Servers", "Open findings", "Critical", "High", "Past SLA", "Due soon",
                     "OS issues", "Application issues", "MBSS failed checks", "Servers with a CS gap"]


class EmailError(RuntimeError):
    """A message the page can show as it is (it never contains the SMTP password)."""


# ------------------------------------------------------------------ settings ----
@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int
    starttls: bool
    use_ssl: bool
    username: str
    password: str
    sender: str

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender)

    def __repr__(self) -> str:   # never print the password
        return (f"SmtpSettings(host={self.host!r}, port={self.port}, starttls={self.starttls}, "
                f"use_ssl={self.use_ssl}, username={self.username!r}, sender={self.sender!r})")


def _flag(text: str, default: bool) -> bool:
    text = text.strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return default


def smtp_settings() -> SmtpSettings:
    """SMTP_* from .env (re-read on every call) or, when blank there, from the process environment."""
    saved = dotenv_values(settings.ENV_FILE) if settings.ENV_FILE.exists() else {}

    def value(name: str) -> str:
        return (saved.get(name) or os.getenv(name) or "").strip()

    use_ssl = _flag(value("SMTP_SSL"), False)
    try:
        port = int(value("SMTP_PORT"))
    except ValueError:
        port = 465 if use_ssl else 587
    return SmtpSettings(host=value("SMTP_HOST"), port=port, starttls=_flag(value("SMTP_STARTTLS"), not use_ssl),
                        use_ssl=use_ssl, username=value("SMTP_USERNAME"), password=value("SMTP_PASSWORD"),
                        sender=value("SMTP_FROM"))


def email_config() -> dict[str, Any]:
    defaults = {"subject": "Security posture: {scope} ({date})", "allowed_recipient_domains": [],
                "max_applications_detailed": 15, "attach_workbook": True, "max_attachment_mb": 20,
                "timeout_seconds": 30}
    return {**defaults, **(settings.load_config().get("email") or {})}


# ---------------------------------------------------------------- recipients ----
_ADDRESS = re.compile(r"^[^@\s,;<>\"']+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def parse_addresses(text: str) -> list[str]:
    """Addresses separated by commas, semicolons or new lines, in order, without repeats."""
    parts = (part.strip() for part in re.split(r"[,;\n]", text or ""))
    return list(dict.fromkeys(part for part in parts if part))


def address_problems(addresses: Iterable[str], allowed_domains: Sequence[str] = ()) -> list[str]:
    """Why some addresses cannot be used (empty list = all fine)."""
    allowed = [domain.strip().lower().lstrip("@") for domain in allowed_domains if str(domain).strip()]
    problems = []
    for address in addresses:
        if not _ADDRESS.match(address):
            problems.append(f"'{address}' is not an email address.")
            continue
        domain = address.rsplit("@", 1)[1].lower()
        if allowed and not any(domain == ok or domain.endswith("." + ok) for ok in allowed):
            problems.append(f"'{address}' is outside the allowed domains ({', '.join(allowed)}).")
    return problems


# ------------------------------------------------------------------ insights ----
def _without_staff(frame: pd.DataFrame, staff_columns: Iterable[str]) -> pd.DataFrame:
    return frame.drop(columns=[c for c in staff_columns if c in frame.columns])


def _servers(frame: pd.DataFrame) -> int:
    return int(frame["Device Name"].nunique()) if not frame.empty and "Device Name" in frame else 0


def headline(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame,
             changes: pd.DataFrame | None = None) -> list[tuple[str, int]]:
    """The headline numbers, in the order they are shown."""
    def count(frame: pd.DataFrame, column: str, values: Sequence[str]) -> int:
        return int(frame[column].isin(values).sum()) if not frame.empty and column in frame else 0

    servers = devices.drop_duplicates("Device Name") if not devices.empty else devices
    numbers = [
        ("Applications", int(devices["Applications"].nunique()) if not devices.empty else 0),
        ("Servers", _servers(devices)),
        ("Production servers", count(servers, "Environment", [env.PROD])),
        ("Development servers", count(servers, "Environment", [env.DEV])),
        ("Open vulnerabilities", len(vulns)),
        ("Unique findings", int(vulns["Title"].nunique()) if not vulns.empty else 0),
        ("Past SLA", count(vulns, "SLA Status", ["Breached"])),
        ("Due soon", count(vulns, "SLA Status", ["Due soon"])),
        ("Critical", count(vulns, "Severity", ["Critical"])),
        ("High", count(vulns, "Severity", ["High"])),
        ("OS issues", count(vulns, "Topic", [classifier.OS])),
        ("Application issues", count(vulns, "Topic", [classifier.APP])),
        ("MBSS failed checks", len(mbss)),
        ("MBSS critical", count(mbss, "Criticality", ["Critical"])),
        ("Servers with a CS gap", _servers(cs[cs["Gaps"] > 0]) if not cs.empty and "Gaps" in cs else 0),
    ]
    if changes is not None and not changes.empty:
        for column in ("New", "Fixed"):
            if column in changes:
                numbers.insert(6 if column == "New" else 7, (f"{column} since the previous report",
                                                             int(changes[column].sum())))
    return numbers


def top_findings(vulns: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    """Findings of one application by servers affected: worst severity, owner and rows past SLA."""
    if vulns.empty:
        return pd.DataFrame(columns=["Finding", "Severity", "Owner", "Servers", "Past SLA"])
    frame = vulns.assign(_rank=vulns["Severity"].map(SEVERITY_RANK).fillna(9),
                         _breached=vulns["SLA Status"].eq("Breached"))
    grouped = frame.groupby("Title", sort=False).agg(
        _rank=("_rank", "min"), Owner=("Topic", "first"), Servers=("Device Name", "nunique"),
        **{"Past SLA": ("_breached", "sum")}).reset_index().rename(columns={"Title": "Finding"})
    grouped["Severity"] = grouped["_rank"].map(dict(enumerate(export.SEVERITIES))).fillna("Unknown")
    grouped = grouped.sort_values(["Servers", "Past SLA", "_rank", "Finding"], ascending=[False, False, True, True])
    return grouped[["Finding", "Severity", "Owner", "Servers", "Past SLA"]].head(limit).astype(
        {"Servers": "int64", "Past SLA": "int64"})


def top_mbss(mbss: pd.DataFrame, limit: int = 5) -> pd.DataFrame:
    """Failed MBSS controls of one application by servers affected."""
    if mbss.empty or "Control Description" not in mbss:
        return pd.DataFrame(columns=["Control", "Criticality", "Servers"])
    rank = {name: index for index, name in enumerate(export.CRITICALITIES)}
    frame = mbss.assign(_rank=mbss["Criticality"].map(rank).fillna(9))
    grouped = frame.groupby("Control Description", sort=False).agg(
        _rank=("_rank", "min"), Servers=("Device Name", "nunique")).reset_index()
    grouped["Criticality"] = grouped["_rank"].map(dict(enumerate(export.CRITICALITIES))).fillna("Unknown")
    grouped["Control"] = grouped["Control Description"].astype(str).str.slice(0, 200)
    grouped = grouped.sort_values(["Servers", "_rank", "Control"], ascending=[False, True, True])
    return grouped[["Control", "Criticality", "Servers"]].head(limit).astype({"Servers": "int64"})


def cs_gaps(cs: pd.DataFrame) -> list[tuple[str, int]]:
    """(control, servers with a gap or partial coverage), controls without a gap left out."""
    if cs.empty:
        return []
    out = []
    for control in CS_CONTROLS:
        column = f"{control} State"
        if column in cs:
            servers = _servers(cs[cs[column].isin(GAP_STATES)])
            if servers:
                out.append((control, servers))
    return sorted(out, key=lambda item: -item[1])


def insights(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame, *,
             changes: pd.DataFrame | None = None, staff_columns: Iterable[str] = export.STAFF_COLUMNS,
             max_applications: int = 15, top_n: int = 10, top_controls: int = 5) -> dict[str, Any]:
    """Everything the email says, as data: headline, per-application table, and detail per application."""
    staff_columns = list(staff_columns)
    vulns, mbss, cs, devices = (_without_staff(frame, staff_columns) for frame in (vulns, mbss, cs, devices))
    summary = export.application_summary(vulns, mbss, cs, devices, changes)
    table = summary[[c for c in APP_TABLE_COLUMNS if c in summary.columns]
                    + [c for c in ("New", "Fixed") if c in summary.columns]]
    details = []
    for application in summary["Application"].head(max(0, int(max_applications))):
        def part(frame: pd.DataFrame) -> pd.DataFrame:
            return frame[frame["Applications"] == application] if not frame.empty else frame
        app_vulns, app_mbss, app_cs = part(vulns), part(mbss), part(cs)
        row = summary[summary["Application"] == application].iloc[0]
        details.append({
            "application": application,
            "line": (f"{int(row['Servers']):,} servers ({int(row['Production']):,} production, "
                     f"{int(row['Development']):,} development) · {int(row['Open findings']):,} open findings, "
                     f"{int(row['Past SLA']):,} past SLA · {int(row['MBSS failed checks']):,} failed MBSS checks · "
                     f"{int(row['Servers with a CS gap']):,} servers with a CS gap"),
            "findings": top_findings(app_vulns, top_n),
            "mbss": top_mbss(app_mbss, top_controls),
            "cs": cs_gaps(app_cs),
        })
    return {"headline": headline(vulns, mbss, cs, devices, changes), "applications": table,
            "details": details, "more": max(0, len(summary) - len(details))}


# -------------------------------------------------------------------- render ----
def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float, np.integer, np.floating)) and not isinstance(value, bool)


def _fmt(value: Any) -> str:
    if _is_number(value) and float(value).is_integer():
        return f"{int(value):,}"
    return str(value)


def _html_table(frame: pd.DataFrame, wide: str = "") -> str:
    head = "".join(f'<th style="text-align:{"left" if c == frame.columns[0] or c in (wide,) else "right"};'
                   f'padding:6px 8px;background:{_PURPLE};color:#fff;font-weight:600;font-size:12px">{_esc(c)}</th>'
                   for c in frame.columns)
    rows = []
    for index, record in enumerate(frame.itertuples(index=False)):
        background = _SOFT if index % 2 else "#fff"
        cells = []
        for column, value in zip(frame.columns, record):
            left = column == frame.columns[0] or column == wide or not _is_number(value)
            text = _esc(value) if left else _fmt(value)
            colour = _RED if column == "Past SLA" and _is_number(value) and value > 0 else _INK
            cells.append(f'<td style="text-align:{"left" if left else "right"};padding:5px 8px;'
                         f'border-bottom:1px solid {_LINE};color:{colour};font-size:13px">{text}</td>')
        rows.append(f'<tr style="background:{background}">{"".join(cells)}</tr>')
    return (f'<table cellspacing="0" cellpadding="0" style="border-collapse:collapse;width:100%;margin:6px 0 14px;'
            f'{_FONT}"><tr>{head}</tr>{"".join(rows)}</table>')


def _heading(text: str, size: int = 16) -> str:
    return f'<h2 style="{_FONT}color:{_PURPLE};font-size:{size}px;margin:18px 0 6px">{_esc(text)}</h2>'


def render_html(info: dict[str, Any], *, scope: str, report_dates: dict[str, str], note: str = "",
                generated_at: datetime, attachment_line: str = "") -> str:
    """The HTML body (a fragment; the page previews it, the message wraps it in a document)."""
    parts = [f'<div style="{_FONT}color:{_INK};max-width:980px">',
             f'<div style="background:{_PURPLE_DARK};color:#fff;padding:16px 20px;border-radius:10px">'
             f'<div style="font-size:11px;letter-spacing:.12em;text-transform:uppercase;opacity:.85">'
             f'Security posture report</div>'
             f'<div style="font-size:20px;font-weight:700;margin-top:4px">{_esc(scope)}</div>'
             f'<div style="font-size:12px;opacity:.85;margin-top:4px">Generated {generated_at:%d %b %Y %H:%M}</div>'
             '</div>']
    if note.strip():
        parts.append(f'<p style="white-space:pre-wrap;font-size:14px;margin:14px 0">{_esc(note.strip())}</p>')
    if report_dates:
        parts.append('<p style="font-size:12px;color:%s;margin:10px 0">%s</p>' % (
            _MUTED, " · ".join(f"{_esc(label)}: {_esc(value)}" for label, value in report_dates.items())))

    cells = "".join(
        f'<td style="padding:8px 10px;border:1px solid {_LINE};vertical-align:top;width:20%">'
        f'<div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:{_PURPLE}">{_esc(label)}</div>'
        f'<div style="font-size:20px;font-weight:700;color:{_RED if label == "Past SLA" and value else _INK}">'
        f'{value:,}</div></td>' + ('</tr><tr>' if index % 5 == 4 else "")
        for index, (label, value) in enumerate(info["headline"]))
    parts += [_heading("Headline numbers"),
              f'<table cellspacing="0" style="border-collapse:collapse;width:100%;{_FONT}"><tr>{cells}</tr></table>']

    if not info["applications"].empty:
        parts += [_heading("By application", 16), _html_table(info["applications"])]
    for detail in info["details"]:
        parts.append(_heading(detail["application"], 15))
        parts.append(f'<p style="font-size:12px;color:{_MUTED};margin:0 0 6px">{_esc(detail["line"])}</p>')
        if not detail["findings"].empty:
            parts.append('<div style="font-size:13px;font-weight:600;margin-top:6px">Top findings by servers affected</div>')
            parts.append(_html_table(detail["findings"]))
        if not detail["mbss"].empty:
            parts.append('<div style="font-size:13px;font-weight:600">Top failed MBSS controls</div>')
            parts.append(_html_table(detail["mbss"]))
        if detail["cs"]:
            listed = ", ".join(f"{_esc(control)} ({servers:,} servers)" for control, servers in detail["cs"])
            parts.append(f'<p style="font-size:13px;margin:4px 0 10px"><b>CS controls with gaps:</b> {listed}</p>')
    if info["more"]:
        parts.append(f'<p style="font-size:12px;color:{_MUTED}">{info["more"]:,} more application(s) are in the '
                     'table above and in the attached workbook, without detail here.</p>')
    parts.append(f'<p style="font-size:12px;color:{_MUTED};margin-top:18px;border-top:1px solid {_LINE};'
                 f'padding-top:8px">{_esc(attachment_line)} No staff names are included. '
                 'Sent from the Security Posture Dashboard.</p></div>')
    return "".join(parts)


def _text_table(frame: pd.DataFrame) -> str:
    if frame.empty:
        return ""
    cells = [[str(c) for c in frame.columns]] + [[_fmt(v) for v in row]
                                                  for row in frame.itertuples(index=False)]
    widths = [min(70, max(len(row[i]) for row in cells)) for i in range(len(frame.columns))]
    lines = ["  ".join(value[:70].ljust(width) if i == 0 else value.rjust(width) if value.replace(",", "").isdigit()
                       else value[:70].ljust(width) for i, (value, width) in enumerate(zip(row, widths)))
             for row in cells]
    lines.insert(1, "  ".join("-" * width for width in widths))
    return "\n".join(line.rstrip() for line in lines)


def render_text(info: dict[str, Any], *, scope: str, report_dates: dict[str, str], note: str = "",
                generated_at: datetime, attachment_line: str = "") -> str:
    lines = [f"Security posture report: {scope}", f"Generated {generated_at:%d %b %Y %H:%M}", ""]
    if note.strip():
        lines += [note.strip(), ""]
    lines += [f"{label}: {value}" for label, value in report_dates.items()]
    lines += ["", "HEADLINE NUMBERS"] + [f"  {label}: {value:,}" for label, value in info["headline"]]
    if not info["applications"].empty:
        lines += ["", "BY APPLICATION", _text_table(info["applications"])]
    for detail in info["details"]:
        lines += ["", detail["application"].upper(), detail["line"]]
        if not detail["findings"].empty:
            lines += ["Top findings by servers affected:", _text_table(detail["findings"])]
        if not detail["mbss"].empty:
            lines += ["Top failed MBSS controls:", _text_table(detail["mbss"])]
        if detail["cs"]:
            lines.append("CS controls with gaps: " + ", ".join(f"{c} ({n:,} servers)" for c, n in detail["cs"]))
    if info["more"]:
        lines += ["", f"{info['more']:,} more application(s) are in the table and the workbook, without detail here."]
    lines += ["", f"{attachment_line} No staff names are included. Sent from the Security Posture Dashboard.".strip()]
    return "\n".join(lines)


# ------------------------------------------------------------------- message ----
def subject_for(template: str, scope: str, when: datetime) -> str:
    try:
        return template.format(scope=scope, date=f"{when:%d %b %Y}")
    except (KeyError, IndexError, ValueError):
        return template


def build_message(vulns: pd.DataFrame, mbss: pd.DataFrame, cs: pd.DataFrame, devices: pd.DataFrame, *,
                  to: Sequence[str], cc: Sequence[str] = (), sender: str = "", subject: str, scope: str,
                  report_dates: dict[str, str] | None = None, note: str = "", attachment: bytes | None = None,
                  attachment_name: str = "security_posture.xlsx", attachment_skipped: str = "",
                  changes: pd.DataFrame | None = None, staff_columns: Iterable[str] = export.STAFF_COLUMNS,
                  max_applications: int = 15, generated_at: datetime | None = None,
                  draft: bool = False, info: dict[str, Any] | None = None) -> EmailMessage:
    """The email for the frames given (already filtered to the chosen applications).

    ``attachment`` is the workbook bytes (export.build_workbook) or None; ``attachment_skipped`` says why
    there is none. ``draft`` marks the message unsent, so Outlook opens a downloaded .eml ready to send.
    ``info`` is an already computed ``insights()`` result for the same frames.
    """
    generated_at = generated_at or datetime.now()
    info = info or insights(vulns, mbss, cs, devices, changes=changes, staff_columns=staff_columns,
                    max_applications=max_applications)
    if attachment is not None:
        line = (f"The attached workbook ({attachment_name}) has every open finding, failed MBSS check and CS gap "
                "for these applications, with the affected servers.")
    else:
        line = attachment_skipped or "No workbook is attached; export it from the dashboard's Overview page."
    options = {"scope": scope, "report_dates": report_dates or {}, "note": note, "generated_at": generated_at,
               "attachment_line": line}

    message = EmailMessage()
    message["Subject"] = subject
    if sender:
        message["From"] = sender
    message["To"] = ", ".join(to)
    if cc:
        message["Cc"] = ", ".join(cc)
    message["Date"] = formatdate(localtime=True)
    domain = sender.rsplit("@", 1)[1] if "@" in sender else "security-posture.local"
    message["Message-ID"] = make_msgid(domain=domain)   # not the machine's host name
    if draft:
        message["X-Unsent"] = "1"
    message.set_content(render_text(info, **options))
    message.add_alternative("<!doctype html><html><body style=\"margin:0;padding:16px;background:#fff\">"
                            + render_html(info, **options) + "</body></html>", subtype="html")
    if attachment is not None:
        message.add_attachment(attachment, maintype=XLSX[0], subtype=XLSX[1], filename=attachment_name)
    return message


def send(message: EmailMessage, config: SmtpSettings, timeout: int = 30) -> list[str]:
    """Send through the configured relay. Returns the recipients it was sent to."""
    if not config.configured:
        raise EmailError("Email is not set up: SMTP_HOST and SMTP_FROM are needed (in .env or the environment).")
    recipients = parse_addresses(", ".join(filter(None, [message.get("To", ""), message.get("Cc", "")])))
    if not recipients:
        raise EmailError("Add at least one recipient.")
    if message.get("From") is None:
        message["From"] = config.sender
    context = ssl.create_default_context()
    try:
        if config.use_ssl:
            client = smtplib.SMTP_SSL(config.host, config.port, timeout=timeout, context=context)
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=timeout)
        with client:
            if config.starttls and not config.use_ssl:
                client.starttls(context=context)
            if config.username:
                client.login(config.username, config.password)
            refused = client.send_message(message, from_addr=config.sender, to_addrs=recipients)
    except smtplib.SMTPAuthenticationError:
        raise EmailError("The mail server refused the SMTP user name or password.") from None
    except smtplib.SMTPRecipientsRefused as error:
        raise EmailError(f"The mail server refused every recipient: {', '.join(error.recipients)}.") from None
    except (smtplib.SMTPException, OSError) as error:
        raise EmailError(f"Could not send through {config.host}:{config.port}: {error}") from None
    return [address for address in recipients if address not in (refused or {})]
