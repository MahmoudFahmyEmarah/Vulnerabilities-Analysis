"""Users (admins only): add accounts, change roles, set passwords, remove accounts."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from tools import auth
from ui import account, theme


def _when(text: str) -> str:
    return text.replace("T", " ")[:16] if text else "never"


def render() -> None:
    if not account.is_admin():
        st.error("Only admins can manage users.")
        return
    me = account.name()
    users = auth.load_users()
    theme.hero("Users · access", "Who can use the dashboard",
               "Admins see every page, including Settings and this one. Platform owners see every page except those "
               "two. Passwords are stored only as salted hashes in " f"{auth.config()['users_file']}.",
               [("Accounts:", str(len(users))), ("Admins:", str(sum(u.get("role") == auth.ADMIN for u in users.values())))])

    with st.container(border=True):
        theme.title("Accounts")
        st.dataframe(pd.DataFrame([{"User": name, "Role": auth.ROLES.get(u.get("role"), u.get("role")),
                                    "Created": _when(u.get("created", "")), "Created by": u.get("created_by", ""),
                                    "Last sign-in": _when(u.get("last_login", ""))}
                                   for name, u in sorted(users.items())]), hide_index=True)

    left, right = st.columns(2)
    with left, st.container(border=True):
        theme.title("Add an account", f"Passwords need at least {auth.config()['min_password_length']} characters. "
                                      "Give the password to the person directly; they can change it from the sidebar.")
        with st.form("add_user", clear_on_submit=True, border=False):
            name = st.text_input("User name", help="Letters, digits, dot, dash, underscore or @.")
            role = st.segmented_control("Role", list(auth.ROLES), format_func=auth.ROLES.get, default=auth.OWNER)
            password = st.text_input("Password", type="password", autocomplete="new-password")
            again = st.text_input("Repeat the password", type="password", autocomplete="new-password")
            if st.form_submit_button("Add account", type="primary", icon=":material/person_add:"):
                try:
                    if password != again:
                        raise auth.AuthError("The two passwords differ.")
                    auth.add_user(name, role or auth.OWNER, password, by=me)
                    st.success(f"Added {auth.normalise(name)}.")
                    st.rerun()
                except auth.AuthError as error:
                    st.error(str(error))

    with right, st.container(border=True):
        theme.title("Change an account")
        picked = st.selectbox("Account", sorted(users), key="u_pick")
        if picked:
            current = users[picked].get("role", auth.OWNER)
            role_column, button_column = st.columns([2, 1], vertical_alignment="bottom")
            new_role = role_column.segmented_control("Role", list(auth.ROLES), format_func=auth.ROLES.get,
                                                     default=current, key=f"u_role_{picked}")
            if button_column.button("Save role", key="u_save_role", disabled=not new_role or new_role == current,
                                    width="stretch"):
                try:
                    auth.set_role(picked, new_role, by=me)
                    st.rerun()
                except auth.AuthError as error:
                    st.error(str(error))
            with st.form("reset_password", clear_on_submit=True, border=False):
                password = st.text_input(f"New password for {picked}", type="password", autocomplete="new-password")
                again = st.text_input("Repeat it", type="password", autocomplete="new-password")
                if st.form_submit_button("Set password", icon=":material/key:"):
                    try:
                        if password != again:
                            raise auth.AuthError("The two passwords differ.")
                        auth.set_password(picked, password, by=me)
                        st.success(f"New password set for {picked}.")
                    except auth.AuthError as error:
                        st.error(str(error))
            confirm = st.checkbox(f"Yes, remove {picked}", key=f"u_confirm_{picked}", disabled=picked == me)
            if st.button("Remove account", key="u_remove", icon=":material/person_remove:",
                         disabled=not confirm or picked == me):
                try:
                    auth.remove_user(picked, by=me)
                    st.rerun()
                except auth.AuthError as error:
                    st.error(str(error))
            if picked == me:
                st.caption("You cannot remove your own account or take the admin role from yourself.")
