"""The signed-in user for this browser session (tools/auth.py holds the accounts).

Signing in lasts until "Sign out", until auth.session_hours have passed, or until the browser
session ends (closing or reloading the page signs you out). With auth.enabled false everyone is
treated as an admin, as before accounts existed.
"""
from __future__ import annotations

import time
from typing import Any

import streamlit as st

from tools import auth

USER = "auth_user"


def current_user() -> dict[str, Any] | None:
    if not auth.enabled():
        return {"name": "", "role": auth.ADMIN}
    user = st.session_state.get(USER)
    if user is None:
        return None
    if time.time() - user["since"] > float(auth.config()["session_hours"]) * 3600:
        st.session_state.pop(USER, None)
        st.session_state["auth_notice"] = "Your session expired. Please sign in again."
        return None
    account = auth.load_users().get(user["name"])
    if account is None:          # removed by an admin since signing in
        st.session_state.pop(USER, None)
        return None
    user["role"] = account.get("role", auth.OWNER)   # a role change applies at once
    return user


def is_admin() -> bool:
    user = current_user()
    return bool(user) and user["role"] == auth.ADMIN


def name() -> str:
    user = current_user()
    return user["name"] if user else ""


def sign_in(user: dict[str, Any]) -> None:
    for key in [k for k in st.session_state if k != USER]:   # nothing from a previous user carries over
        del st.session_state[key]
    st.session_state[USER] = {**user, "since": time.time()}


def sign_out() -> None:
    st.session_state.clear()


def sidebar() -> None:
    """Who is signed in, change password, sign out."""
    user = current_user()
    if not user or not auth.enabled():
        return
    with st.sidebar:
        st.divider()
        st.caption(f"Signed in as **{user['name']}** · {auth.ROLES.get(user['role'], user['role'])}")
        left, right = st.columns(2)
        with left.popover("Password", icon=":material/key:", width="stretch"):
            with st.form("own_password", clear_on_submit=True, border=False):
                current = st.text_input("Current password", type="password")
                new = st.text_input("New password", type="password",
                                    help=f"At least {auth.config()['min_password_length']} characters.")
                again = st.text_input("Repeat the new password", type="password")
                if st.form_submit_button("Change password", type="primary"):
                    try:
                        stored = auth.load_users().get(user["name"], {}).get("password", "")
                        if not auth.check_password(current, stored):
                            raise auth.AuthError("The current password is wrong.")
                        if new != again:
                            raise auth.AuthError("The two new passwords differ.")
                        auth.set_password(user["name"], new, by=user["name"])
                        st.success("Password changed.")
                    except auth.AuthError as error:
                        st.error(str(error))
        if right.button("Sign out", icon=":material/logout:", width="stretch", key="sign_out"):
            auth.audit("signed out", user["name"])
            sign_out()
            st.rerun()
