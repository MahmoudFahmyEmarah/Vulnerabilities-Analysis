"""Settings: model endpoint, report files, environment mapping, classifier, policy, logs."""
from __future__ import annotations

from dataclasses import replace
from datetime import date, datetime, time
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import set_key

import settings
from agents import base_agent
from agents.base_agent import AgentError
from agents.classifier import TopicClassifierAgent
from memory.knowledge_base import KnowledgeBase
from observability import tracing
from tools import classifier, data_loader as dl, environment as env
from tools.saudi_calendar import SaudiCalendar
from ui import state, theme


def _save_env(values: dict[str, str]) -> None:
    settings.ENV_FILE.touch(exist_ok=True)
    for name, value in values.items():
        set_key(str(settings.ENV_FILE), name, value, quote_mode="never")


def _model_section() -> None:
    config = base_agent.llm_settings()
    editable = settings.model_settings_editable()
    has_key = config.api_key not in ("", "not-needed")
    with st.container(border=True):
        theme.title("Model endpoint", "Any OpenAI-compatible server (vLLM, Ollama, TGI, LiteLLM). Only the endpoint is required.")
        if not editable:
            st.info("The endpoint applies to every user, so it is set where the app is hosted (LLM_BASE_URL, LLM_MODEL "
                    "and LLM_API_KEY on the CML Application) and is read-only here. Set MODEL_SETTINGS_EDITABLE=1 "
                    "on the application to allow changes from this page.", icon=":material/lock:")
        one, two, three = st.columns([3, 2, 2])
        url = one.text_input("Endpoint (base URL ending in /v1)", value=config.base_url, key="set_url",
                             placeholder="http://llm-host:8000/v1", disabled=not editable)
        model = two.text_input("Model name (blank = ask the endpoint)", value=config.model, key="set_model",
                               placeholder="gpt-oss-120b", disabled=not editable)
        # The saved key is never sent to the browser: the field starts empty and blank keeps the saved key.
        key = three.text_input("API key (if the server needs one)", type="password", key="set_key", value="",
                               placeholder="A key is saved; blank keeps it" if has_key else "No key saved",
                               disabled=not editable)
        forget = editable and has_key and three.checkbox("Remove the saved key", key="set_key_clear")
        api_key = key.strip() or ("not-needed" if forget else config.api_key)
        test, save, _ = st.columns([1, 1, 4])
        if test.button("Test connection", key="set_test", width="stretch"):
            candidate = base_agent.LLMSettings(**{**config.__dict__, "base_url": url.strip().rstrip("/"),
                                                  "model": model.strip(), "api_key": api_key})
            try:
                served = base_agent.list_models(candidate, refresh=True)
                chosen = base_agent.resolve_model(candidate)
                st.success(f"Connected. The endpoint serves: {', '.join(served) or 'no models'}. "
                           f"The app will use **{chosen}**.")
            except AgentError as error:
                st.error(str(error))
        if editable and save.button("Save", type="primary", key="set_save", width="stretch"):
            values = {"LLM_BASE_URL": url.strip().rstrip("/"), "LLM_MODEL": model.strip()}
            if key.strip() or forget:   # otherwise the saved key stays as it is
                values["LLM_API_KEY"] = key.strip() or "not-needed"
            _save_env(values)
            st.success("Saved to .env. New requests use it immediately. A blank endpoint falls back to the "
                       "LLM_BASE_URL environment variable, if one is set.")
        st.caption("Scan text sent to the model is limited to whitelisted fields; names of people are never sent. "
                   "Rules: guardrails/policies.yaml → llm_input.")


_DATE_SOURCE = {
    "Last Scan Date Time": "the latest Last Scan Date Time in the file",
    "Evaluation Date": "the latest Evaluation Date in the file",
    dl.FILE_DATE: "the date the workbook was saved (this report has no date column)",
    dl.USER_DATE: "a date set below",
}
_SOURCE_SHORT = {"Last Scan Date Time": "latest scan", "Evaluation Date": "latest evaluation",
                 dl.FILE_DATE: "workbook saved"}
_KINDS = (dl.VULN, dl.MBSS, dl.CS)
_UPLOADED = " (uploaded)"


def _files_section(data: state.Data) -> None:
    with st.container(border=True):
        theme.title("Report files", f"Read from {settings.data_dir()}. Each file is dated by the data inside it; the "
                                    "newest of each kind is used unless you pick another. The Trends page compares weeks.")
        if message := st.session_state.pop("set_files_saved", None):
            st.success(message)
        found = dl.describe_files(settings.data_dir())
        columns = st.columns(3)
        for column, kind in zip(columns, _KINDS):
            by_name = {info.path.name: info for info in found[kind]}
            if by_name:
                column.selectbox(dl.KIND_LABEL[kind], list(by_name), key=f"file::{kind}",
                                 format_func=lambda name, infos=by_name: f"{name} · {infos[name].report_date:%d %b %Y}")
                chosen = by_name.get(st.session_state.get(f"file::{kind}")) or found[kind][0]
                column.caption(f"Report date {chosen.report_date:%d %b %Y}, from {_DATE_SOURCE[chosen.date_source]}"
                               + (f" (the file itself gives {chosen.found_date:%d %b %Y})."
                                  if chosen.date_source == dl.USER_DATE else ".")
                               + (f" {chosen.rows:,} rows." if chosen.rows else "")
                               + (f" {len(by_name)} files of this kind." if len(by_name) > 1 else ""))
                for skipped in chosen.skipped_sheets:
                    column.warning(f"Skipped {skipped}", icon=":material/warning:")
            else:
                column.warning(f"{dl.KIND_LABEL[kind]}: no file found.")
            if kind in data.errors:
                column.error(data.errors[kind])
        _report_weeks(found)
        _upload_reports(found)


def _as_day(value, fallback: date) -> date:
    """A date from the editor (date, Timestamp or blank)."""
    try:
        stamp = pd.Timestamp(value)
    except (TypeError, ValueError):
        return fallback
    return fallback if pd.isna(stamp) else stamp.date()


def _moved(info: dl.FileInfo, day: date) -> dl.FileInfo:
    """``info`` as it will be with report date ``day``: its own date again when ``day`` is that date."""
    if day == info.found_date.date():
        return replace(info, report_date=info.found_date, date_source=info.found_source, found=None)
    if day == info.report_date.date():
        return info
    return replace(info, report_date=datetime.combine(day, time()), date_source=dl.USER_DATE,
                   found=(info.found_date, info.found_source))


def _date_table(infos: list[dl.FileInfo], notes: list[str] | None = None) -> pd.DataFrame:
    table = pd.DataFrame({
        "Report": [dl.KIND_LABEL.get(info.kind, "—") for info in infos],
        "File": [info.path.name for info in infos],
        "Date in the file": [f"{info.found_date:%d %b %Y} ({_SOURCE_SHORT.get(info.found_source, info.found_source)})"
                             for info in infos],
        "Report date": [info.report_date.date() for info in infos],
        "Rows": [info.rows for info in infos],
    })
    if notes is not None:
        table["Note"] = notes
    return table


_DATE_COLUMN = st.column_config.DateColumn(
    "Report date", format="DD MMM YYYY",
    help="The week this file counts for. Files dated within three days of each other form one week. "
         "Set it back to the date in the file to undo.")


def _weeks_table(infos: list[dl.FileInfo], uploaded: frozenset[str] = frozenset()) -> pd.DataFrame:
    """Which file lands in which weekly set: one row per week, one column per report."""
    rows = []
    for week in state.week_sets(info for info in infos if info.error is None):
        row = {"Week": week.label}
        for kind in _KINDS:
            info = week.files.get(kind)
            row[dl.KIND_LABEL[kind]] = "" if info is None else info.path.name + (
                _UPLOADED if info.path in uploaded else "")
        rows.append(row)
    return pd.DataFrame(rows, columns=["Week", *(dl.KIND_LABEL[kind] for kind in _KINDS)])


def _alone(infos: list[dl.FileInfo], paths: set) -> list[str]:
    """Names of the files in ``paths`` that would make up a week on their own while other weeks exist."""
    weeks = state.week_sets(info for info in infos if info.error is None)
    if len(weeks) < 2:
        return []
    return [week.files[kind].path.name for week in weeks for kind in week.files
            if len(week.files) == 1 and week.files[kind].path in paths]


def _report_weeks(found: dict[str, list[dl.FileInfo]]) -> None:
    infos = [info for kind in _KINDS for info in found[kind]]
    if not infos:
        return
    st.markdown("**Report weeks**")
    st.caption("Change *Report date* when a file lands in the wrong week, for example a CS Controls workbook that "
               "was saved some days after the scans. The weeks below update before you save.")
    round_ = st.session_state.setdefault("set_dates_round", 0)
    table = _date_table(infos)
    edited = st.data_editor(table, key=f"set_dates_{round_}", hide_index=True,
                            disabled=[column for column in table.columns if column != "Report date"],
                            column_config={"Report date": _DATE_COLUMN})
    days = [_as_day(value, info.report_date.date()) for value, info in zip(edited["Report date"], infos)]
    after = [_moved(info, day) for info, day in zip(infos, days)]
    changed = [(info, day) for info, day, moved in zip(infos, days, after) if moved.report_date != info.report_date]
    st.dataframe(_weeks_table(after), hide_index=True)
    for name in _alone(after, {info.path for info, _ in changed}):
        st.warning(f"{name} would be a week of its own. If it belongs with other reports, give it their date.",
                   icon=":material/warning:")
    if changed and st.button(f"Save {len(changed)} report date(s)", type="primary", key="set_dates_save"):
        for info, day in changed:
            dl.set_report_date(info.path, None if day == info.found_date.date() else day)
        state.use_newest_files({info.kind for info, _ in changed})
        st.session_state["set_dates_round"] = round_ + 1
        st.session_state["set_files_saved"] = f"Saved the report date of {len(changed)} file(s)."
        st.rerun()


def _check_upload(path: Path) -> tuple[dl.FileInfo | None, str]:
    """The upload's report type and dates, or why it cannot be used (then it is not saved)."""
    kind = dl.sniff_kind(path)
    if kind is None:
        return None, "Not one of the three reports: not saved."
    info = dl.file_info(kind, path)
    if info.error:
        return info, f"Cannot be read: {info.error} Not saved."
    return info, ""


def _upload_reports(found: dict[str, list[dl.FileInfo]]) -> None:
    round_ = st.session_state.setdefault("set_upload_round", 0)
    uploads = st.file_uploader("Add report files (.xlsx)", type=["xlsx"], accept_multiple_files=True,
                               key=f"set_upload_{round_}") or []
    staged: dict[str, tuple[Path, dl.FileInfo | None, str]] = st.session_state.setdefault("set_staged", {})
    for file_id in [file_id for file_id in staged if file_id not in {upload.file_id for upload in uploads}]:
        dl.discard_upload(staged.pop(file_id)[0])      # removed from the upload box
    if not uploads:
        return
    with st.spinner("Reading the uploaded files to find their report dates. A large report takes about half a minute."):
        for upload in uploads:
            if upload.file_id not in staged:
                path = dl.stage_upload(upload.name, upload.getbuffer())
                staged[upload.file_id] = (path, *_check_upload(path))
    entries = [staged[upload.file_id] for upload in uploads]
    existing = {info.path.name for kind in _KINDS for info in found[kind]}
    seen: set[str] = set()
    notes, usable = [], []
    for path, info, problem in entries:
        if not problem and path.name in seen:
            problem = "Another upload has the same name: not saved."
        seen.add(path.name)
        notes.append(problem or ("Replaces the file of the same name." if path.name in existing else ""))
        usable.append(not problem)
    infos = [info or dl.FileInfo(path, "", dl.file_date(path), dl.FILE_DATE) for path, info, _ in entries]

    st.markdown("**Check the uploaded files**")
    table = _date_table(infos, notes)
    edited = st.data_editor(table, key=f"set_upload_dates_{round_}", hide_index=True,
                            disabled=[column for column in table.columns if column != "Report date"],
                            column_config={"Report date": _DATE_COLUMN})
    days = [_as_day(value, info.report_date.date()) for value, info in zip(edited["Report date"], infos)]
    ready = [(info, day) for info, day, ok in zip(infos, days, usable) if ok]
    if not ready:
        st.warning("None of these files can be saved.")
        return
    replaced = {info.path.name for info, _ in ready}
    after = ([info for kind in _KINDS for info in found[kind] if info.path.name not in replaced]
             + [_moved(info, day) for info, day in ready])
    st.caption("Weeks after saving:")
    st.dataframe(_weeks_table(after, frozenset(info.path for info, _ in ready)), hide_index=True)
    for name in _alone(after, {info.path for info, _ in ready}):
        st.warning(f"{name} would be a week of its own. If it belongs with other reports, give it their date.",
                   icon=":material/warning:")
    if st.button(f"Save {len(ready)} file(s)", type="primary", key="set_upload_save"):
        saved, failed = [], []
        for info, day in ready:
            try:
                target = dl.adopt_upload(info.path, settings.data_dir())
                dl.set_report_date(target, None if day == info.found_date.date() else day)
                saved.append(target.name)
            except OSError as error:
                failed.append(f"{info.path.name} ({error})")
        for path, _, _ in staged.values():
            if path.exists():
                dl.discard_upload(path)
        staged.clear()
        if failed:
            st.error(f"Could not save {', '.join(failed)}. Close the file if it is open elsewhere and try again.")
            return
        state.use_newest_files({info.kind for info, _ in ready})
        st.session_state["set_upload_round"] = round_ + 1
        st.session_state["set_dates_round"] = st.session_state.get("set_dates_round", 0) + 1
        st.session_state["set_files_saved"] = f"Saved {', '.join(saved)}. Every page now uses them."
        st.rerun()


def _environment_section(data: state.Data) -> None:
    with st.container(border=True):
        theme.title("Environment mapping",
                    "Servers with no known environment are treated as production. Set the environment per application here.")
        platform = st.session_state.get("f_platform", state.ALL)
        devices = data.devices if platform == state.ALL else data.devices[data.devices["Platform"] == platform]
        st.caption(f"Showing {platform if platform != state.ALL else 'all platforms'} (sidebar Platform filter).")
        counts = devices.groupby("Env Source")["Device Name"].nunique()
        theme.badges([(f"{source}: {count:,} servers", "red" if source == env.SRC_ASSUMED else "gray")
                      for source, count in counts.items()])
        try:
            overrides = env.load_overrides(settings.overrides_file())
        except Exception as error:  # noqa: BLE001 - do not offer a save that would overwrite the file
            st.error(f"Could not read {settings.overrides_file().name}: {error}. Fix or remove the file to edit "
                     "the mapping here. Until then every server is treated as production.")
            return
        # The mapping applies to exactly the servers counted here: those with no confirmed environment, or
        # already set in the override file. Servers that the AI inventory, the application name or the
        # server list place keep their environment, so mapping an application never flips them.
        editable_sources = [env.SRC_ASSUMED, env.SRC_OVERRIDE]
        shown_apps = devices.loc[devices["Env Source"].isin(editable_sources), "Applications"].dropna().unique()
        everywhere = data.devices[data.devices["Applications"].isin(shown_apps)]   # all platforms of those apps
        editable = everywhere[everywhere["Env Source"].isin(editable_sources)]
        members = {app: sorted(group["Device Name"].dropna().unique())
                   for app, group in editable.groupby("Applications")}
        placed = everywhere[~everywhere["Env Source"].isin(editable_sources)].groupby("Applications")["Device Name"].nunique()
        table = pd.DataFrame({
            "Applications": list(members),
            "Platform": [", ".join(sorted(editable.loc[editable["Applications"] == app, "Platform"].dropna().unique()))
                         for app in members],
            "Servers": [len(servers) for servers in members.values()],
            "Already placed (not changed)": [int(placed.get(app, 0)) for app in members],
            "Environment": [env.mapped_environment(overrides, app, servers) for app, servers in members.items()],
        }).sort_values("Servers", ascending=False, ignore_index=True)
        edited = st.data_editor(
            table, hide_index=True, key="set_env_editor", height=340,
            disabled=["Applications", "Platform", "Servers", "Already placed (not changed)"],
            column_config={
                "Servers": st.column_config.NumberColumn(
                    "Servers", help="Servers this mapping applies to: no confirmed environment, or set here before."),
                "Already placed (not changed)": st.column_config.NumberColumn(
                    help="Servers of this application whose environment comes from the AI inventory, the "
                         "application name or the server list. Saving a mapping does not change them."),
                "Environment": st.column_config.SelectboxColumn(
                    "Environment", options=[env.PROD, env.DEV],
                    help="Leave blank to keep the safe default (production)."),
            })
        if st.button("Save environment mapping", type="primary", key="set_env_save"):
            before = dict(zip(table["Applications"], table["Environment"]))
            chosen = {app: (value if isinstance(value, str) and value else None)
                      for app, value in zip(edited["Applications"], edited["Environment"])
                      if (value if isinstance(value, str) and value else None) != before.get(app)}
            if not chosen:
                st.info("Nothing changed.")
            else:
                env.save_overrides(settings.overrides_file(), env.remap_applications(overrides, members, chosen))
                servers = sum(len(members[app]) for app in chosen)
                st.success(f"Saved {len(chosen)} application mapping(s) for {servers} server(s) to "
                           f"{settings.overrides_file().name}.")
                st.rerun()
        st.caption("For single servers, add rows with a Device Name to reference/environment_overrides.csv. "
                   "Servers in the AI Platforms Inventory take their environment from it "
                   f"({settings.load_config()['app'].get('ai_inventory', 'not configured')}).")


def _classifier_section(data: state.Data) -> None:
    with st.container(border=True):
        theme.title("OS / application classification")
        if data.vulns.empty:
            st.caption("Load a vulnerability report first.")
            return
        unmatched = data.vulns.loc[data.vulns["Topic Rule"] == classifier.UNMATCHED_RULE, "Title"]
        titles = sorted(unmatched.unique())
        st.write(f"Rules classify {1 - len(unmatched) / len(data.vulns):.2%} of open findings. "
                 f"**{len(titles)}** unique titles ({len(unmatched):,} findings) match no rule and default to "
                 "application issues.")
        if titles:
            with st.expander("Unmatched titles"):
                st.dataframe(unmatched.value_counts().rename_axis("Title").reset_index(name="Findings"), hide_index=True)
            if st.button("Classify them with the model", key="set_classify", disabled=not base_agent.is_configured(),
                         icon=":material/auto_awesome:"):
                try:
                    with st.spinner(f"Labelling {len(titles)} titles…"):
                        labels, details = TopicClassifierAgent().classify(titles)
                    KnowledgeBase().save_topic_labels(labels, f"model:{details.get('model', '')}")
                    st.success(f"Labelled {len(labels)} titles. They now show as 'AI / manual label'.")
                    st.rerun()
                except AgentError as error:
                    st.error(str(error))
        st.caption("Rules live in tools/classifier.py; the golden set in evals/golden_set.jsonl checks them.")


def _policy_section() -> None:
    policies = settings.load_policies()
    calendar = SaudiCalendar(policies)
    with st.container(border=True):
        theme.title("Change-window policy", "Edit guardrails/policies.yaml to change it. The schedule guardrail enforces it.")
        hours, production = policies["calendar"]["working_hours"], policies["production"]
        theme.facts([
            ("Time zone", policies["calendar"]["timezone"]),
            ("Working days", ", ".join(policies["calendar"]["working_days"])),
            ("Working hours", f"{hours['start']}–{hours['end']}"),
            ("Production windows", f"every night {production['night_window']['start']}–{production['night_window']['end']}; "
                                   f"weekend days {production['weekend_day_window']['start']}–{production['weekend_day_window']['end']}"),
            ("Holiday freeze", "on" if calendar.freeze else "off"),
            ("Development", "any time"),
            ("Next freeze days", ", ".join(f"{day:%d %b %Y} ({name})" for day, name in
                                           calendar.upcoming_holidays(calendar.now().date(), 200)[:6]) or "none in 200 days"),
        ])


def _logs_section() -> None:
    with st.expander("Knowledge base (stored recommendations)"):
        records = KnowledgeBase().recommendations()
        st.dataframe(records, hide_index=True) if not records.empty else st.caption("Nothing stored yet.")
    with st.expander("Model call log (observability/logs/llm_calls.jsonl)"):
        calls = tracing.recent()
        st.dataframe(calls, hide_index=True) if not calls.empty else st.caption("No model calls yet.")


def render() -> None:
    data = state.load()
    theme.hero("Settings", "Configuration",
               "Connect the self-hosted model, choose the report files, confirm which servers are production, and "
               "review the change-window policy.", [])
    _model_section()
    _files_section(data)
    _environment_section(data)
    _classifier_section(data)
    _policy_section()
    _logs_section()
