"""Reusable page pieces: the AI recommendation panel, table helpers, downloads."""
from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

import settings
from agents import base_agent
from agents.base_agent import AgentError
from memory.knowledge_base import KnowledgeBase
from ui import theme
from workflows import recommend

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


def render_recommendation(result: dict[str, Any], key: str) -> None:
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
    stored = {"like": 1, "dislike": 0}.get(result.get("feedback") or "")
    vote = st.feedback("thumbs", key=f"fb-{key}-{result['id']}", default=stored)
    if vote is not None and vote != stored:
        KnowledgeBase().set_feedback(result["id"], "like" if vote == 1 else "dislike")
        result["feedback"] = "like" if vote == 1 else "dislike"
        st.toast("Thanks. A disliked answer is not reused; ask again to get a new one."
                 if vote == 0 else "Thanks. This answer will be reused for the same finding.")


def recommendation_panel(check_type: str, row: dict[str, Any], key: str) -> None:
    """Button + answer for one finding. Answers are stored and reused across users."""
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
            render_recommendation(result, key)
        elif configured:
            st.caption("No stored answer for this finding yet.")
