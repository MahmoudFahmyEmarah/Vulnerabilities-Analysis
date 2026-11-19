"""Security Posture Dashboard — vulnerabilities, MBSS and CS Controls with AI remediation and fix scheduling.

Run:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

import settings
from agents import base_agent
from ui import state, theme
from ui.views import cs_controls, mbss, overview, schedule, settings_page, trends, vulnerabilities

st.set_page_config(page_title=settings.load_config()["app"]["title"], page_icon=":material/shield:", layout="wide")
theme.inject()

page = st.navigation(
    [
        st.Page(overview.render, title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
        st.Page(vulnerabilities.render, title="Vulnerabilities", icon=":material/bug_report:", url_path="vulnerabilities"),
        st.Page(mbss.render, title="MBSS", icon=":material/rule:", url_path="mbss"),
        st.Page(cs_controls.render, title="CS Controls", icon=":material/verified_user:", url_path="cs-controls"),
        st.Page(trends.render, title="Trends", icon=":material/trending_up:", url_path="trends"),
        st.Page(schedule.render, title="Fix Schedule", icon=":material/event:", url_path="schedule"),
        st.Page(settings_page.render, title="Settings", icon=":material/settings:", url_path="settings"),
    ],
    position="top",
)

data = state.load()
state.sidebar_filters(data)
with st.sidebar:
    st.divider()
    if base_agent.is_configured():
        st.caption(f"Model endpoint: {base_agent.llm_settings().base_url}")
    else:
        st.caption("Model endpoint: not configured (Settings).")

page.run()
