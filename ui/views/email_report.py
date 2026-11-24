"""Email report: the numbers and main findings for chosen applications, with the Excel workbook attached."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

import settings
from tools import data_loader as dl, environment as env, history
from ui import state, theme
from ui.views import overview
from workflows import email_report as mail, export

ALL_APPS = "All applications in scope"
_WORKBOOKS: dict[tuple, bytes] = {}   # the last workbooks built, so Send and Download do not build twice
_INSIGHTS: dict[tuple, dict] = {}     # the email body's numbers, so typing a recipient does not recount them


def _base_frames(data: state.Data) -> tuple[pd.DataFrame, ...]:
    """The sidebar scope (platform, environment, team / inventory switches) without its application filter."""
    return tuple(state._scope(frame, applications=False) for frame in (data.vulns, data.mbss, data.cs, data.devices))


def _resolve(picked: list[str], options: list[str], ai_platforms: list[str]) -> list[str]:
    if not picked or ALL_APPS in picked:
        return list(options)
    apps = set(picked) - {state.AI_GROUP}
    if state.AI_GROUP in picked:
        apps |= set(ai_platforms)
    return sorted(apps & set(options), key=str.casefold)


def _scope_label(picked: list[str], apps: list[str]) -> str:
    session = st.session_state
    parts = [session.get("f_platform", state.ALL) if session.get("f_platform", state.ALL) != state.ALL
             else "All platforms"]
    if session.get("f_env") in (env.PROD, env.DEV):
        parts.append(session["f_env"])
    if session.get("f_team"):
        parts.append("team servers")
    if session.get("f_inventory"):
        parts.append("AI inventory servers")
    if picked and ALL_APPS not in picked:
        others = [app for app in picked if app != state.AI_GROUP]
        named = ["AI platforms"] if state.AI_GROUP in picked else []
        if others:
            named.append(others[0] if len(others) == 1 else f"{len(others)} applications")
        parts.append(" + ".join(named) if named else f"{len(apps)} applications")
    else:
        parts.append("all applications")
    return " · ".join(parts)


def _changes(data: state.Data, apps: list[str]) -> pd.DataFrame | None:
    """New / Fixed per application against the previous week (as on the Overview page), for these applications."""
    loaded = data.files.get(dl.VULN)
    if loaded is None:
        return None
    weeks = state.weeks()
    index = next((i for i, week in enumerate(weeks) if dl.VULN in week.files
                  and week.files[dl.VULN].path.resolve() == loaded.resolve()), None)
    if index is None:
        return None
    previous = next((week for week in weeks[index + 1:] if dl.VULN in week.files), None)
    if previous is None:
        return None
    changes = state.changes(dl.VULN, weeks[index], previous, data)
    if changes is None:
        return None
    changes = state._scope(changes, applications=False)
    return history.count_changes(changes[changes["Applications"].isin(apps)])


def _file_key(data: state.Data) -> tuple:
    def one(path: Path | None) -> tuple:
        return (str(path), path.stat().st_mtime_ns) if path and path.exists() else (str(path),)
    return tuple(sorted((kind, one(path)) for kind, path in data.files.items()))


def _insights(key: tuple, frames: tuple[pd.DataFrame, ...], **options) -> dict:
    if key not in _INSIGHTS:
        while len(_INSIGHTS) >= 4:
            _INSIGHTS.pop(next(iter(_INSIGHTS)))
        _INSIGHTS[key] = mail.insights(*frames, **options)
    return _INSIGHTS[key]


def _workbook(key: tuple, frames: tuple[pd.DataFrame, ...], options: dict) -> bytes:
    """Build (or reuse) the workbook. Runs inside a download callback too, so it does not use session state."""
    if key not in _WORKBOOKS:
        while len(_WORKBOOKS) >= 2:
            _WORKBOOKS.pop(next(iter(_WORKBOOKS)))
        _WORKBOOKS[key] = export.build_workbook(*frames, **options)
    return _WORKBOOKS[key]


def render() -> None:
    data = state.load()
    config = settings.load_config()
    policies = settings.load_policies()
    mail_config = mail.email_config()
    smtp = mail.smtp_settings()
    timezone = policies["calendar"]["timezone"]

    vulns, mbss, cs, devices = _base_frames(data)
    options = sorted(devices["Applications"].dropna().unique(), key=str.casefold) if not devices.empty else []
    ai_platforms = [app for app in options if app in data.ai_platforms]
    choices = [ALL_APPS] + ([state.AI_GROUP] if ai_platforms else []) + options

    theme.hero(
        "Email report · share the insights",
        "Email the posture of chosen applications",
        "Pick one platform, several applications or all of them. The email gives the headline numbers, a table per "
        "application and each application's main findings, with the Excel workbook for those applications attached. "
        "Server addresses and staff names are not written in the email body.",
        [("Scope:", state.scope_label()), ("Email relay:", "set up" if smtp.configured else "not set up")],
    )
    for message in data.errors.values():
        st.error(message)
    if devices.empty:
        st.info("No report files were found for this scope. Add the Excel reports on the Settings page.")
        return

    if "e_apps" not in st.session_state:   # start from the sidebar's choice
        sidebar = [app for app in st.session_state.get("f_apps", []) if app in choices]
        st.session_state["e_apps"] = sidebar or [ALL_APPS]
    st.session_state["e_apps"] = [app for app in st.session_state["e_apps"] if app in choices]

    with st.container(border=True):
        picked = st.multiselect(
            "Applications", choices, key="e_apps", placeholder=ALL_APPS,
            help=(f"*{ALL_APPS}* follows the sidebar's platform and environment. "
                  + (f"*{state.AI_GROUP}* picks {', '.join(ai_platforms)}." if ai_platforms else "")))
        apps = _resolve(picked, options, ai_platforms)
        if not apps:
            st.info("Pick at least one application.")
            return

        def part(frame: pd.DataFrame) -> pd.DataFrame:
            return frame[frame["Applications"].isin(apps)] if not frame.empty else frame

        frames = (part(vulns), part(mbss), part(cs), part(devices))
        p_vulns, p_mbss, p_cs, p_devices = frames
        breached = int((p_vulns["SLA Status"] == "Breached").sum()) if not p_vulns.empty else 0
        theme.kpis([
            {"label": "Applications", "value": theme.number(len(apps)), "tone": "primary",
             "sub": f"{p_devices['Device Name'].nunique():,} servers"},
            {"label": "Open vulnerabilities", "value": theme.number(len(p_vulns)),
             "sub": f"{p_vulns['Title'].nunique():,} unique" if not p_vulns.empty else "none in scope"},
            {"label": "Past SLA", "value": theme.number(breached), "tone": "alert",
             "sub": f"{theme.percent(breached, len(p_vulns))} of open findings"},
            {"label": "MBSS failed checks", "value": theme.number(len(p_mbss)), "sub": "failing baseline controls"},
            {"label": "Servers with a CS gap",
             "value": theme.number(int((p_cs["Gaps"] > 0).sum()) if not p_cs.empty else 0), "sub": "CS controls"},
        ])

    scope = _scope_label(picked, apps)
    now = datetime.now(ZoneInfo(timezone))
    report_dates = {
        "Vulnerability report as of": state.as_of(data.vulns, "Last Scan Date Time"),
        "MBSS report as of": state.as_of(data.mbss, "Evaluation Date"),
        "CS Controls report dated": overview._cs_date(data.files.get(dl.CS)),
    }
    staff_columns = policies["llm_input"].get("never_send", export.STAFF_COLUMNS)
    changes = _changes(data, apps)
    book_options = {"scope": scope, "report_dates": report_dates, "timezone": timezone,
                    "due_soon_days": int(config["sla_due_soon_days"]), "staff_columns": staff_columns,
                    "changes": changes}
    key = (tuple(apps), scope, _file_key(data), len(p_devices), int((p_devices["Environment"] == env.PROD).sum()))

    with st.container(border=True):
        theme.title("Message")
        left, right = st.columns(2)
        to_text = left.text_input("To", key="e_to", placeholder="name@example.com; team@example.com")
        cc_text = right.text_input("Cc", key="e_cc", placeholder="Optional")
        subject = st.text_input("Subject", value=mail.subject_for(str(mail_config["subject"]), scope, now),
                                key=f"e_subject::{scope}")
        note = st.text_area("Note at the top of the email", key="e_note", height=90,
                            placeholder="Optional, for example what you need from the recipients and by when.")
        attach = st.toggle("Attach the Excel workbook", value=bool(mail_config["attach_workbook"]), key="e_attach",
                           help="The same workbook as Overview → Export to Excel, for the chosen applications only. "
                                "It is built when you send or download (a few seconds for large scopes).")

        to, cc = mail.parse_addresses(to_text), mail.parse_addresses(cc_text)
        problems = mail.address_problems(to + cc, mail_config.get("allowed_recipient_domains") or [])
        for problem in problems:
            st.error(problem)
        if key in _WORKBOOKS and attach:
            st.caption(f"Workbook: {len(_WORKBOOKS[key]) / 1_048_576:.1f} MB.")

    limit = float(mail_config.get("max_attachment_mb") or 0) * 1_048_576
    detailed = int(mail_config["max_applications_detailed"])
    info = _insights(key + (detailed,), frames, changes=changes, staff_columns=staff_columns,
                     max_applications=detailed)

    def message(draft: bool):
        blob, skipped = None, ""
        if attach:
            blob = _workbook(key, frames, book_options)
            if limit and len(blob) > limit:
                skipped = (f"The workbook ({len(blob) / 1_048_576:.1f} MB) is larger than the "
                           f"{mail_config['max_attachment_mb']} MB limit, so it is not attached; export it from "
                           "the dashboard's Overview page.")
                blob = None
        return mail.build_message(
            *frames, to=to, cc=cc, sender=smtp.sender, subject=subject, scope=scope, report_dates=report_dates,
            note=note, attachment=blob, attachment_skipped=skipped, changes=changes, staff_columns=staff_columns,
            attachment_name=f"security_posture_{now:%Y-%m-%d}.xlsx".replace(" ", "_"),
            max_applications=detailed, generated_at=now, draft=draft, info=info)

    one, two, three = st.columns([1.2, 1.2, 3], vertical_alignment="center")
    can_send = smtp.configured and bool(to) and not problems
    clicked = one.button("Send email", type="primary", icon=":material/send:", disabled=not can_send,
                         key="e_send", width="stretch")
    two.download_button("Download .eml", lambda: message(draft=True).as_bytes(), key="e_eml",
                        file_name=f"security_posture_{now:%Y-%m-%d}.eml", mime="message/rfc822",
                        icon=":material/download:", width="stretch",
                        help="Opens in Outlook as a new message, ready to check and send yourself.")
    if not smtp.configured:
        three.caption("Sending is off: set SMTP_HOST and SMTP_FROM (and SMTP_USERNAME / SMTP_PASSWORD if the relay "
                      "needs a login) in .env or the application's environment variables. The .eml download works "
                      "without them.")
    elif not to:
        three.caption("Add at least one recipient to send.")
    if clicked:
        try:
            with st.spinner("Building the workbook and sending…" if attach else "Sending…"):
                outgoing = message(draft=False)
                sent = mail.send(outgoing, smtp, timeout=int(mail_config.get("timeout_seconds", 30)))
            attached = any(part.get_filename() for part in outgoing.iter_attachments())
            st.success(f"Sent to {len(sent)} recipient(s)" + (" with the workbook attached." if attached else "."),
                       icon=":material/mark_email_read:")
        except mail.EmailError as error:
            st.error(str(error))

    with st.container(border=True):
        theme.title("Preview", "The email body as recipients will see it (the attachment is not shown).")
        with st.container(height=640, border=False):
            st.html(mail.render_html(info, scope=scope, report_dates=report_dates, note=note, generated_at=now,
                                     attachment_line=("The Excel workbook for these applications is attached."
                                                      if attach else "No workbook is attached.")))
