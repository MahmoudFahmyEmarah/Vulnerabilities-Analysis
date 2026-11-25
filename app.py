"""Security Posture Dashboard — vulnerabilities, MBSS and CS Controls with AI remediation and fix scheduling.

Run:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

import settings
from agents import base_agent
from tools import auth
from ui import account, state, theme
from ui.views import (cs_controls, email_report, login, mbss, overview, remote, schedule, settings_page, trends, users,
                      vulnerabilities)

st.set_page_config(page_title=settings.load_config()["app"]["title"], page_icon=":material/shield:", layout="wide")
theme.inject()

user = account.current_user()
if user is None:   # nothing is loaded or shown before sign-in
    st.navigation([st.Page(login.render, title="Sign in", icon=":material/login:", url_path="login")],
                  position="hidden").run()
    st.stop()

pages = {
    "overview": st.Page(overview.render, title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
    "vulnerabilities": st.Page(vulnerabilities.render, title="Vulnerabilities", icon=":material/bug_report:",
                               url_path="vulnerabilities"),
    "mbss": st.Page(mbss.render, title="MBSS", icon=":material/rule:", url_path="mbss"),
    "cs": st.Page(cs_controls.render, title="CS Controls", icon=":material/verified_user:", url_path="cs-controls"),
    "trends": st.Page(trends.render, title="Trends", icon=":material/trending_up:", url_path="trends"),
    "schedule": st.Page(schedule.render, title="Fix Schedule", icon=":material/event:", url_path="schedule"),
    "remote": st.Page(remote.render, title="Run on servers", icon=":material/terminal:", url_path="run"),
    "email": st.Page(email_report.render, title="Email report", icon=":material/mail:", url_path="email"),
}
if user["role"] == auth.ADMIN:   # platform owners never get these two pages
    pages["settings"] = st.Page(settings_page.render, title="Settings", icon=":material/settings:", url_path="settings")
    if auth.enabled():
        pages["users"] = st.Page(users.render, title="Users", icon=":material/group:", url_path="users")
state.set_pages(pages)
page = st.navigation(list(pages.values()), position="top")

data = state.load()
state.sidebar_filters(data)
with st.sidebar:
    st.divider()
    if base_agent.is_configured():
        st.caption(f"Model endpoint: {base_agent.llm_settings().base_url}")
    else:
        st.caption("Model endpoint: not configured" + (" (Settings)." if user["role"] == auth.ADMIN else "."))
account.sidebar()

page.run()
