"""Sign-in page: the only page shown until a user has signed in."""
from __future__ import annotations

import streamlit as st

import settings
from tools import auth
from ui import account, theme


def render() -> None:
    config = settings.load_config()["app"]
    _, middle, _ = st.columns([1, 1.4, 1])
    with middle:
        theme.hero("Security posture · " + config.get("team", ""), config.get("title", "Security Posture Dashboard"),
                   "Sign in to continue.")
        notice = st.session_state.pop("auth_notice", "")
        if notice:
            st.info(notice)
        if not auth.load_users():
            st.warning("No accounts exist yet. Create the first admin in a terminal in the project folder, then "
                       "reload this page:", icon=":material/person_add:")
            st.code("python -m tools.auth add <name> --role admin", language="bash")
            return
        with st.container(border=True):
            with st.form("sign_in", border=False):
                name = st.text_input("User name", autocomplete="username")
                password = st.text_input("Password", type="password", autocomplete="current-password")
                submitted = st.form_submit_button("Sign in", type="primary", icon=":material/login:", width="stretch")
            if submitted:
                try:
                    account.sign_in(auth.sign_in(name, password))
                    st.rerun()
                except auth.AuthError as error:
                    st.error(str(error))
        st.caption("Forgot your password? Ask an admin to set a new one. Reloading the page signs you out.")
