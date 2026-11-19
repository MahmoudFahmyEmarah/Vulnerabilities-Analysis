"""Settings: model endpoint, report files, environment mapping, classifier, policy, logs."""
from __future__ import annotations

import os

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
    with st.container(border=True):
        theme.title("Model endpoint", "Any OpenAI-compatible server (vLLM, Ollama, TGI, LiteLLM). Only the endpoint is required.")
        one, two, three = st.columns([3, 2, 2])
        url = one.text_input("Endpoint (base URL ending in /v1)", value=config.base_url, key="set_url",
                             placeholder="http://llm-host:8000/v1")
        model = two.text_input("Model name (blank = ask the endpoint)", value=config.model, key="set_model",
                               placeholder="gpt-oss-120b")
        key = three.text_input("API key (if the server needs one)", type="password", key="set_key",
                               value="" if config.api_key == "not-needed" else config.api_key)
        test, save, _ = st.columns([1, 1, 4])
        if test.button("Test connection", key="set_test", width="stretch"):
            candidate = base_agent.LLMSettings(**{**config.__dict__, "base_url": url.strip().rstrip("/"),
                                                  "model": model.strip(), "api_key": key.strip() or "not-needed"})
            try:
                served = base_agent.list_models(candidate, refresh=True)
                chosen = base_agent.resolve_model(candidate)
                st.success(f"Connected. The endpoint serves: {', '.join(served) or 'no models'}. "
                           f"The app will use **{chosen}**.")
            except AgentError as error:
                st.error(str(error))
        if save.button("Save", type="primary", key="set_save", width="stretch"):
            _save_env({"LLM_BASE_URL": url.strip().rstrip("/"), "LLM_MODEL": model.strip(),
                       "LLM_API_KEY": key.strip() or "not-needed"})
            st.success("Saved to .env. New requests use it immediately. A blank endpoint falls back to the "
                       "LLM_BASE_URL environment variable, if one is set.")
        st.caption("Scan text sent to the model is limited to whitelisted fields; names of people are never sent. "
                   "Rules: guardrails/policies.yaml → llm_input.")


_DATE_SOURCE = {
    "Last Scan Date Time": "the latest Last Scan Date Time in the file",
    "Evaluation Date": "the latest Evaluation Date in the file",
    dl.FILE_DATE: "the date the workbook was saved (this report has no date column)",
}


def _files_section(data: state.Data) -> None:
    with st.container(border=True):
        theme.title("Report files", f"Read from {settings.data_dir()}. Each file is dated by the data inside it; the "
                                    "newest of each kind is used unless you pick another. The Trends page compares weeks.")
        found = dl.describe_files(settings.data_dir())
        columns = st.columns(3)
        for column, kind in zip(columns, (dl.VULN, dl.MBSS, dl.CS)):
            by_name = {info.path.name: info for info in found[kind]}
            if by_name:
                column.selectbox(dl.KIND_LABEL[kind], list(by_name), key=f"file::{kind}",
                                 format_func=lambda name, infos=by_name: f"{name} · {infos[name].report_date:%d %b %Y}")
                chosen = by_name.get(st.session_state.get(f"file::{kind}")) or found[kind][0]
                column.caption(f"Report date {chosen.report_date:%d %b %Y}, from {_DATE_SOURCE[chosen.date_source]}."
                               + (f" {chosen.rows:,} rows." if chosen.rows else "")
                               + (f" {len(by_name)} files of this kind." if len(by_name) > 1 else ""))
                for skipped in chosen.skipped_sheets:
                    column.warning(f"Skipped {skipped}", icon=":material/warning:")
            else:
                column.warning(f"{dl.KIND_LABEL[kind]}: no file found.")
            if kind in data.errors:
                column.error(data.errors[kind])
        uploads = st.file_uploader("Add report files (.xlsx)", type=["xlsx"], accept_multiple_files=True, key="set_upload")
        if uploads and st.button("Save uploaded files", key="set_upload_save"):
            settings.data_dir().mkdir(parents=True, exist_ok=True)
            saved, skipped = [], []
            for upload in uploads:
                target = settings.data_dir() / os.path.basename(upload.name)
                target.write_bytes(upload.getbuffer())
                (saved if dl.sniff_kind(target) else skipped).append(upload.name)
            if saved:
                st.success(f"Saved: {', '.join(saved)}. Reload the page to use them.")
            if skipped:
                st.warning(f"Saved but not recognised as one of the three reports: {', '.join(skipped)}.")


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
        overrides = env.load_overrides(settings.overrides_file())
        by_app = dict(zip(overrides["Applications"], overrides["Environment"]))
        assumed = devices[devices["Env Source"].isin([env.SRC_ASSUMED, env.SRC_OVERRIDE])]
        table = (assumed.groupby(["Platform", "Applications"])["Device Name"].nunique().reset_index(name="Servers")
                 .sort_values("Servers", ascending=False))
        table["Environment"] = table["Applications"].map(by_app)
        edited = st.data_editor(
            table, hide_index=True, key="set_env_editor", height=340, disabled=["Platform", "Applications", "Servers"],
            column_config={"Environment": st.column_config.SelectboxColumn(
                "Environment", options=[env.PROD, env.DEV], help="Leave blank to keep the safe default (production).")})
        if st.button("Save environment mapping", type="primary", key="set_env_save"):
            # Keep per-server rows and mappings of applications that are not in this table; replace the rest.
            keep = overrides[overrides["Device Name"].notna() | ~overrides["Applications"].isin(edited["Applications"])]
            chosen = edited.dropna(subset=["Environment"])[["Applications", "Environment"]].assign(**{"Device Name": None})
            env.save_overrides(settings.overrides_file(), pd.concat([keep, chosen], ignore_index=True))
            st.success(f"Saved {len(chosen)} application mapping(s) to {settings.overrides_file().name}.")
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
