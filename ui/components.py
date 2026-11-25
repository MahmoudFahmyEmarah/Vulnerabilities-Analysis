"""Reusable page pieces: the AI recommendation panel, table helpers, downloads."""
from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

import settings
from agents import base_agent
from agents.base_agent import AgentError
from memory.knowledge_base import KnowledgeBase
from ui import state, theme
from workflows import playbook, recommend

_RESTART = {"none": ("No restart", "gray"), "service": ("Service restart", "orange"), "host": ("Host reboot", "red")}


def selected_row(event: Any) -> int | None:
    """Index of the row picked in an st.dataframe(on_select='rerun') table, or None."""
    rows = event.selection.rows if event and getattr(event, "selection", None) else []
    return rows[0] if rows else None


def capped_table(frame: pd.DataFrame, key: str, download_name: str, **kwargs: Any) -> Any:
    """Show at most ui.max_table_rows rows and offer the complete table as CSV. Returns the table's event."""
    limit = int(settings.load_config()["ui"]["max_table_rows"])
    event = st.dataframe(frame.head(limit), hide_index=True, key=key, **kwargs)
    left, right = st.columns([3, 1])
    if len(frame) > limit:
        left.caption(f"Showing the first {limit:,} of {len(frame):,} rows. The download has all of them.")
    # The CSV is built only when the button is clicked, so large tables do not slow every rerun.
    right.download_button("Download CSV", lambda: frame.to_csv(index=False).encode("utf-8-sig"),
                          file_name=download_name, mime="text/csv", key=f"{key}-download", width="stretch")
    return event


def render_recommendation(result: dict[str, Any], key: str, finding: dict[str, Any] | None = None,
                          servers: pd.DataFrame | None = None) -> None:
    content = result["content"]
    st.markdown(f"**{content.get('summary', '')}**")
    restart_text, restart_tone = _RESTART.get(content.get("restart_required", "none"), _RESTART["none"])
    chips = [(restart_text, restart_tone),
             ("Downtime expected" if content.get("downtime_expected") else "No downtime expected",
              "red" if content.get("downtime_expected") else "gray")]
    if content.get("estimated_minutes_per_server"):
        chips.append((f"~{content['estimated_minutes_per_server']} min per server", ""))
    source = "From the knowledge base" if result["source"] == "knowledge base" else "Generated now"
    chips.append((f"{source}{' · ' + result['model'] if result.get('model') else ''}", "solid"))
    theme.badges(chips)

    for warning in result.get("warnings", []):
        st.warning(warning, icon=":material/warning:")
    if content.get("root_cause"):
        st.markdown(f"**Why it is flagged.** {content['root_cause']}")
    if content.get("prerequisites"):
        st.markdown("**Before you start**\n" + "\n".join(f"- {item}" for item in content["prerequisites"]))

    st.markdown("**Steps**")
    for number, step in enumerate(content.get("steps", []), 1):
        st.markdown(f"{number}. **{step.get('title', '')}**" + (f"  \n   {step['detail']}" if step.get("detail") else ""))
        if step.get("commands"):
            st.code("\n".join(step["commands"]), language="bash")
    for heading, field in (("Verify", "verification"), ("Roll back", "rollback")):
        if content.get(field):
            st.markdown(f"**{heading}**")
            st.code("\n".join(content[field]), language="bash")
    if content.get("caveats"):
        st.markdown("**Confirm before running**\n" + "\n".join(f"- {item}" for item in content["caveats"]))

    st.caption("AI-generated guidance. Review it against the vendor advisory and test in development first.")
    _use_it(result, key, finding or {}, servers)
    stored = {"like": 1, "dislike": 0}.get(result.get("feedback") or "")
    vote = st.feedback("thumbs", key=f"fb-{key}-{result['id']}", default=stored)
    if vote is not None and vote != stored:
        KnowledgeBase().set_feedback(result["id"], "like" if vote == 1 else "dislike")
        result["feedback"] = "like" if vote == 1 else "dislike"
        st.toast("Thanks. A disliked answer is not reused; ask again to get a new one."
                 if vote == 0 else "Thanks. This answer will be reused for the same finding.")


def _use_it(result: dict[str, Any], key: str, finding: dict[str, Any], servers: pd.DataFrame | None) -> None:
    """Take the recommendation further: an Ansible playbook to review and run, or the Run on servers page."""
    content = result["content"]
    commands = [command for step in content.get("steps", []) for command in step.get("commands", [])]
    hosts = list(dict.fromkeys(servers["Device Name"])) if servers is not None and "Device Name" in servers else []
    title = str(finding.get("Title") or finding.get("Control Description") or finding.get("Control") or key)
    parallel = int(settings.load_policies()["scheduling"]["max_parallel_servers"])
    left, right, _ = st.columns([1.6, 1.4, 2])
    left.download_button(
        "Download Ansible playbook", lambda: playbook.finding_bundle(content, finding, servers, parallel=parallel,
                                                                     model=result.get("model", "")),
        file_name=f"ansible_{playbook.group_name(title)[:60]}.zip", mime="application/zip", key=f"pb-{key}-{result['id']}",
        icon=":material/download:", width="stretch",
        help=f"playbook.yml with these steps as tasks, and inventory.ini with the {len(hosts)} affected server(s). "
             "Risky commands and commands with a placeholder are left out as comments. It targets development "
             "unless you pass -e target=production.")
    if right.button("Run on servers…", key=f"run-{key}-{result['id']}", icon=":material/terminal:", width="stretch",
                    disabled=not commands or "remote" not in state.pages(),
                    help="Open the Run on servers page with these commands and the affected servers filled in."):
        for stale in ("r_command", "r_hosts", "r_apps", "r_confirm", "remote_results"):
            st.session_state.pop(stale, None)
        st.session_state["remote_prefill"] = {"title": title, "commands": commands, "servers": hosts}
        st.switch_page(state.pages()["remote"])


def recommendation_panel(check_type: str, row: dict[str, Any], key: str, servers: pd.DataFrame | None = None) -> None:
    """Button + answer for one finding. Answers are stored and reused across users.

    ``servers`` (rows with Device Name, Environment and OS columns) feed the Ansible export and Run on servers.
    """
    state_key = f"rec::{check_type}::{key}"
    result = st.session_state.get(state_key) or recommend.cached_recommendation(check_type, row)
    if result and result.get("feedback") == "dislike":
        result = None

    with st.container(border=True):
        theme.title("AI recommendation")
        configured = base_agent.is_configured()
        label = "Regenerate" if result else "Recommend a fix"
        clicked = st.button(label, type="secondary" if result else "primary", key=f"btn-{state_key}",
                            icon=":material/auto_awesome:", disabled=not configured)
        if not configured:
            st.info("No model endpoint is configured yet. Add it on the Settings page to get recommendations.")
        if clicked:
            try:
                with st.spinner("Asking the model…"):
                    result = recommend.get_recommendation(check_type, row, force=bool(result))
                st.session_state[state_key] = result
            except AgentError as error:
                st.error(str(error))
        if result:
            render_recommendation(result, key, row, servers)
        elif configured:
            st.caption("No stored answer for this finding yet.")
