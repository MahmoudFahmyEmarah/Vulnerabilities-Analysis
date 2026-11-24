"""Run on servers: sign in over SSH for this browser session and run one command on one or many servers.

The login is kept only in this browser session's memory (tools/remote.py): it is never saved, and it
expires after remote_run.session_minutes without use, on Disconnect, or when the session ends.
"""
from __future__ import annotations

from datetime import timedelta

import pandas as pd
import streamlit as st

from guardrails.output_checks import command_problems
from tools import environment as env, remote
from tools.saudi_calendar import SaudiCalendar
from ui import state, theme
import settings

LOGIN, KEYS, CHECKS, RESULTS = "remote_login", "remote_trusted_keys", "remote_checks", "remote_results"
PREFILL = "remote_prefill"   # set by the AI recommendation panel: {"title", "commands", "servers"}


def _servers(data: state.Data, devices: pd.DataFrame) -> pd.DataFrame:
    """Servers in scope with their operating system and host name from the vulnerability report."""
    table = devices[["Device Name", "Applications", "Environment"]].drop_duplicates("Device Name").copy()
    extra = [c for c in ("Operating System", "Host Name") if c in data.vulns.columns]
    if extra:
        per_server = data.vulns.drop_duplicates("Device Name").set_index("Device Name")[extra]
        table = table.join(per_server, on="Device Name")
    for column in ("Operating System", "Host Name"):
        if column not in table:
            table[column] = ""
    table["Windows"] = table["Operating System"].astype("string").str.lower().str.contains("windows").fillna(False)
    return table.sort_values(["Applications", "Environment", "Device Name"]).reset_index(drop=True)


def _login() -> remote.Login | None:
    login = st.session_state.get(LOGIN)
    if login is not None and login.expired:
        login.forget()
        st.session_state.pop(LOGIN, None)
        st.session_state.pop(KEYS, None)
        st.session_state.pop(CHECKS, None)
        st.warning("Your login expired, so it was forgotten. Sign in again to continue.")
        return None
    return login


def _disconnect() -> None:
    login = st.session_state.pop(LOGIN, None)
    if login is not None:
        login.forget()
    for key in (KEYS, CHECKS, RESULTS):
        st.session_state.pop(key, None)


def _pick_servers(table: pd.DataFrame, rules: dict) -> list[str]:
    prefill = st.session_state.get(PREFILL) or {}
    with st.container(border=True):
        theme.title("1 · Servers", "Servers in the sidebar scope. Pick an application and environment, then the servers.")
        one, two = st.columns([2, 1.2])
        applications = sorted(table["Applications"].dropna().unique(), key=str.casefold)
        wanted = [h for h in prefill.get("servers", []) if h in set(table["Device Name"])]
        default_apps = sorted(set(table.loc[table["Device Name"].isin(wanted), "Applications"].dropna())) if wanted else []
        picked_apps = one.multiselect("Applications", applications, default=default_apps, key="r_apps",
                                      placeholder="All applications in scope")
        environments = two.pills("Environment", [env.DEV, env.PROD], selection_mode="multi", key="r_env",
                                 default=[env.DEV, env.PROD])
        shown = table
        if picked_apps:
            shown = shown[shown["Applications"].isin(picked_apps)]
        if environments:
            shown = shown[shown["Environment"].isin(environments)]
        labels = {row["Device Name"]: " · ".join(str(v) for v in (row["Device Name"], row["Host Name"], row["Applications"],
                                                                   row["Environment"]) if pd.notna(v) and str(v))
                  for _, row in shown.iterrows()}
        if "r_hosts" not in st.session_state and wanted:
            st.session_state["r_hosts"] = [h for h in wanted if h in labels]
        current = [h for h in st.session_state.get("r_hosts", []) if h in labels]
        if current != st.session_state.get("r_hosts", []):
            st.session_state["r_hosts"] = current
        left, right = st.columns([5, 1], vertical_alignment="bottom")
        if right.button("Select all", key="r_all", width="stretch", disabled=not labels):
            st.session_state["r_hosts"] = list(labels)[: int(rules["max_servers_per_run"])]
        hosts = left.multiselect("Servers", list(labels), format_func=labels.get, key="r_hosts",
                                 max_selections=int(rules["max_servers_per_run"]),
                                 help=f"At most {rules['max_servers_per_run']} servers per run (remote_run in "
                                      "guardrails/policies.yaml).")
        if rules.get("allow_other_hosts"):
            typed = st.text_input("Other servers (comma separated)", key="r_other",
                                  help="Allowed by remote_run.allow_other_hosts. They are treated as production.")
            hosts += [h.strip() for h in typed.replace(";", ",").split(",") if h.strip() and h.strip() not in hosts]
        if hosts:
            chosen = table[table["Device Name"].isin(hosts)]
            production = int((chosen["Environment"] == env.PROD).sum()) + len(set(hosts) - set(chosen["Device Name"]))
            theme.badges([(f"{len(hosts)} server(s)", "solid"),
                          (f"{production} production", "red" if production else "gray"),
                          (f"{int(chosen['Windows'].sum())} Windows", "gray")])
    return hosts


def _sign_in(hosts: list[str], rules: dict) -> remote.Login | None:
    login = _login()
    with st.container(border=True):
        theme.title("2 · Sign in", f"Your credentials stay in this browser session's memory only. They are never "
                                   f"saved, and are forgotten after {rules['session_minutes']} minutes without use, "
                                   "when you disconnect, or when you close the page.")
        if login is not None:
            left, right = st.columns([4, 1], vertical_alignment="center")
            left.markdown(f"Signed in as **{login.username}** with a {login.method} on port {login.port}. "
                          f"Expires in about {login.minutes_left} min unless used.")
            if right.button("Disconnect", key="r_disconnect", icon=":material/logout:", width="stretch"):
                _disconnect()
                st.rerun()
            return login
        with st.form("r_login", clear_on_submit=True, border=False):
            one, two, three = st.columns([2, 1.4, 0.8])
            username = one.text_input("User name", autocomplete="off")
            method = two.segmented_control("Sign in with", ["Password", "Private key"], default="Password")
            port = three.number_input("Port", 1, 65535, 22)
            password = st.text_input("Password", type="password", autocomplete="off",
                                     help="Also used for sudo unless you give a sudo password below.")
            key_text = st.text_area("Private key (OpenSSH format)", height=100, placeholder="-----BEGIN OPENSSH PRIVATE KEY-----",
                                    help="Only used with 'Private key'. Pasted, never uploaded or saved.")
            four, five = st.columns(2)
            passphrase = four.text_input("Key passphrase", type="password", autocomplete="off")
            sudo_password = five.text_input("sudo password (if different)", type="password", autocomplete="off")
            submitted = st.form_submit_button("Connect", type="primary", icon=":material/login:", disabled=not hosts)
        if not hosts:
            st.caption("Pick at least one server first.")
        if submitted:
            if not username or (method != "Private key" and not password) or (method == "Private key" and not key_text):
                st.error("Enter the user name and a password or private key.")
                return None
            login = remote.Login(username.strip(), password=password if method != "Private key" else "",
                                 private_key=key_text if method == "Private key" else "", passphrase=passphrase,
                                 sudo_password=sudo_password, port=int(port), minutes=int(rules["session_minutes"]))
            try:
                login.key()
            except ValueError as error:
                st.error(str(error))
                return None
            with st.spinner(f"Checking host keys on {len(hosts)} server(s)…"):
                st.session_state[CHECKS] = remote.scan_host_keys(hosts, login.port, int(rules["max_parallel"]))
            st.session_state[LOGIN] = login
            st.rerun()
    return None


def _host_keys(hosts: list[str], login: remote.Login, rules: dict) -> list[str]:
    """Show the host-key check; returns the servers that can be used (known key or accepted for this session)."""
    trusted: dict[str, remote.HostKey] = st.session_state.setdefault(KEYS, {})
    checks = {c.host: c for c in st.session_state.get(CHECKS, []) if c.port == login.port}
    missing = [h for h in hosts if h not in checks]
    if missing:
        with st.spinner(f"Checking host keys on {len(missing)} server(s)…"):
            for check in remote.scan_host_keys(missing, login.port, int(rules["max_parallel"])):
                checks[check.host] = check
        st.session_state[CHECKS] = list(checks.values())
    rows = [checks[h] for h in hosts]
    new = [c for c in rows if c.status == "new" and c.host not in trusted]
    changed = [c for c in rows if c.status == "CHANGED"]
    unreachable = [c for c in rows if c.status == "unreachable"]
    accepted = sum(c.status == "new" and c.host in trusted for c in rows)
    with st.expander(f"Host keys: {sum(c.status == 'known' for c in rows)} known, {accepted} accepted for this "
                     f"session, {len(new)} new, {len(changed)} changed, {len(unreachable)} unreachable",
                     expanded=bool(new or changed)):
        st.dataframe(pd.DataFrame([{"Server": c.host, "Status": "accepted for this session"
                                    if c.host in trusted and c.status == "new" else c.status,
                                    "Key type": c.key_type, "Fingerprint": c.fingerprint, "Error": c.error}
                                   for c in rows]), hide_index=True)
        if changed:
            st.error(f"{len(changed)} server(s) present a different host key from the one recorded in known_hosts. "
                     "They are left out. Check with the server owner before connecting.")
        if new:
            st.caption("New keys are not in known_hosts. Compare the fingerprints with the server owner or your own "
                       "~/.ssh/known_hosts before you accept them. Accepting lasts for this session only.")
            if st.button(f"Accept {len(new)} new host key(s) for this session", key="r_accept"):
                trusted.update({c.host: c for c in new})
                st.rerun()
    return [c.host for c in rows if c.status == "known" or (c.status == "new" and c.host in trusted)]


def _command(rules: dict) -> tuple[str, str]:
    prefill = st.session_state.get(PREFILL) or {}
    with st.container(border=True):
        theme.title("3 · Command", "Runs as one script on every server. Linux: bash; Windows (OpenSSH): the default shell.")
        if prefill.get("commands") and "r_command" not in st.session_state:
            st.session_state["r_command"] = "\n".join(prefill["commands"])
        if prefill.get("title"):
            st.caption(f"Loaded from the AI recommendation for: {prefill['title']}. Review every line before running.")
        command = st.text_area("Command", key="r_command", height=150, placeholder="e.g. rpm -q openssl")
    return command.strip(), "ai recommendation" if prefill.get("commands") else "typed"


def _results(results: list[remote.Result]) -> None:
    ok = sum(r.status == "OK" for r in results)
    theme.kpis([{"label": "Servers", "value": str(len(results)), "tone": "primary"},
                {"label": "Succeeded", "value": str(ok), "sub": "exit code 0"},
                {"label": "Failed", "value": str(sum(r.status == "Failed" for r in results)),
                 "tone": "alert" if any(r.status == "Failed" for r in results) else "", "sub": "non-zero exit code"},
                {"label": "Not run", "value": str(sum(r.status == "Error" for r in results)),
                 "sub": "login, host key or time-out"}])
    table = pd.DataFrame([{"Server": r.host, "Result": r.status, "Exit code": r.exit_code, "Seconds": r.seconds,
                           "First line": (r.error or (r.stdout or r.stderr).strip().splitlines()[0]
                                          if (r.error or (r.stdout or r.stderr).strip()) else "")}
                          for r in results])
    st.dataframe(table, hide_index=True)
    st.download_button("Download results (CSV)", pd.DataFrame([{
        "Server": r.host, "Result": r.status, "Exit code": r.exit_code, "Seconds": r.seconds, "Error": r.error,
        "Output": r.stdout, "Errors": r.stderr} for r in results]).to_csv(index=False).encode("utf-8-sig"),
        file_name="remote_run_results.csv", mime="text/csv", key="r_download")
    for r in results:
        with st.expander(f"{r.host} · {r.status}" + (f" · exit {r.exit_code}" if r.exit_code is not None else "")):
            if r.error:
                st.error(r.error)
            if r.stdout:
                st.code(r.stdout, language=None, wrap_lines=True)
            if r.stderr:
                st.markdown("**Errors**")
                st.code(r.stderr, language=None, wrap_lines=True)
            if r.truncated:
                st.caption(f"Output cut at {remote.policy()['output_limit_kb']} KB.")


def render() -> None:
    rules = remote.policy()
    data = state.load()
    _, _, _, devices = state.filtered(data)
    theme.hero("Run on servers · SSH", "Run a command on one or many servers",
               "Sign in once for this browser session, pick the servers and run one command on all of them. "
               "Risky commands and commands with a placeholder are refused, production needs your confirmation, and "
               "every run is written to the audit log (who, where, what, exit codes; never passwords or output).",
               [("Scope:", state.scope_label()), ("Per run:", f"up to {rules['max_servers_per_run']} servers")])
    if not rules.get("enabled", True):
        st.info("Running commands from the dashboard is switched off (remote_run.enabled in guardrails/policies.yaml).")
        return
    if devices.empty:
        st.info("No servers in this scope. Check the sidebar filters or add the reports on the Settings page.")
        return

    table = _servers(data, devices)
    hosts = _pick_servers(table, rules)
    login = _sign_in(hosts, rules)
    command, source = _command(rules)
    if login is None or not hosts:
        return
    usable = _host_keys(hosts, login, rules)

    with st.container(border=True):
        theme.title("4 · Run")
        chosen = table[table["Device Name"].isin(usable)]
        windows = set(chosen.loc[chosen["Windows"], "Device Name"])
        production = [h for h in usable if h not in set(chosen["Device Name"])
                      or chosen.loc[chosen["Device Name"] == h, "Environment"].iloc[0] == env.PROD]
        one, two, three, four = st.columns(4)
        sudo = one.toggle("Run with sudo", key="r_sudo", help="Linux servers only. Uses the sudo password, or the "
                                                              "login password when none is given.")
        stop = two.toggle("Stop at the first error", value=True, key="r_stop", help="Adds 'set -e' on Linux.")
        parallel = three.number_input("Servers at once", 1, int(rules["max_parallel"]),
                                      min(5, int(rules["max_parallel"])), key="r_parallel")
        timeout = four.number_input("Time-out (seconds)", 10, 3600, int(rules["command_timeout_seconds"]), key="r_timeout")

        problems = command_problems(command) if command else []
        for problem in problems:
            st.error(f"Not run: the command {problem}.")
        confirmed = True
        if production and command and not problems:
            calendar = SaudiCalendar(settings.load_policies())
            now = calendar.now()
            daytime = calendar.overlaps_working_hours(now, now + timedelta(seconds=int(timeout)))
            if daytime:
                st.warning("It is Saudi working hours. Production changes are only allowed outside working hours; "
                           "run only read-only checks on production now.")
            confirmed = st.checkbox(f"I have an approved change (or this is a read-only check) for running this on "
                                    f"{len(production)} production server(s) now.", key="r_confirm")
        left_out = len(hosts) - len(usable)
        if left_out:
            st.caption(f"{left_out} server(s) are left out: unknown or changed host key, or unreachable.")
        run_column, test_column, _ = st.columns([1.4, 1.2, 3])
        if test_column.button("Test login", key="r_test", icon=":material/key:", disabled=not usable, width="stretch",
                              help="Logs in and out on each server without running anything."):
            with st.spinner(f"Logging in on {len(usable)} server(s)…"):
                login.touch()
                st.session_state[RESULTS] = remote.check_logins(usable, login, st.session_state.get(KEYS, {}),
                                                                int(rules["max_parallel"]))
        if run_column.button(f"Run on {len(usable)} server(s)", type="primary", icon=":material/play_arrow:",
                             key="r_run", width="stretch",
                             disabled=not (command and usable and confirmed) or bool(problems)):
            with st.spinner(f"Running on {len(usable)} server(s)…"):
                results = remote.run(usable, command, login, st.session_state.get(KEYS, {}), windows_hosts=windows,
                                     sudo=sudo, stop_on_error=stop, parallel=int(parallel), timeout=int(timeout))
            headers = st.context.headers or {}
            remote.audit(user=login.username, viewer=headers.get("Remote-User") or headers.get("X-Forwarded-User") or "",
                         hosts=usable, command=command, sudo=sudo, results=results, source=source)
            st.session_state[RESULTS] = results
        if st.session_state.get(RESULTS):
            _results(st.session_state[RESULTS])
