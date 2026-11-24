"""Run a command on servers over SSH, for the "Run on servers" page.

Credentials: a Login lives only in the browser session's memory (Streamlit session state). It is never
written to disk, logged, cached or sent to the model, its repr hides the secrets, and it is forgotten
after ``remote_run.session_minutes`` without use, when the user disconnects, or when the browser
session ends.

Host keys: a server is only trusted when its key is in ~/.ssh/known_hosts (or the known_hosts file the
policy names) or the user has accepted the fingerprint shown for this session. A changed key is never
accepted.

Audit: every run appends one line to observability/logs/remote_runs.jsonl with who ran what where and
the exit codes; never passwords, keys or command output.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import shlex
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko

import settings

AUDIT_FILE = settings.LOG_DIR / "remote_runs.jsonl"


def policy() -> dict[str, Any]:
    defaults = {"enabled": True, "session_minutes": 30, "command_timeout_seconds": 300, "max_servers_per_run": 50,
                "max_parallel": 10, "output_limit_kb": 256, "allow_other_hosts": False, "known_hosts_file": "",
                "connect_timeout_seconds": 10}
    return {**defaults, **(settings.load_policies().get("remote_run") or {})}


# ------------------------------------------------------------------ login ----
@dataclass
class Login:
    """SSH credentials for one browser session. Never persisted."""

    username: str
    password: str = field(default="", repr=False)
    private_key: str = field(default="", repr=False)
    passphrase: str = field(default="", repr=False)
    sudo_password: str = field(default="", repr=False)
    port: int = 22
    minutes: int = 30
    expires_at: float = 0.0

    def __post_init__(self) -> None:
        self.touch()

    def touch(self) -> None:
        self.expires_at = time.time() + self.minutes * 60

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def minutes_left(self) -> int:
        return max(0, int((self.expires_at - time.time()) // 60))

    @property
    def method(self) -> str:
        return "private key" if self.private_key else "password"

    def key(self) -> paramiko.PKey | None:
        if not self.private_key:
            return None
        errors = []
        for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                return kind.from_private_key(io.StringIO(self.private_key), password=self.passphrase or None)
            except paramiko.PasswordRequiredException as error:
                raise ValueError("The private key is protected: enter its passphrase.") from error
            except (paramiko.SSHException, ValueError) as error:
                errors.append(str(error))
        raise ValueError("The private key could not be read (OpenSSH Ed25519, ECDSA or RSA keys are supported).")

    def forget(self) -> None:
        self.password = self.private_key = self.passphrase = self.sudo_password = ""
        self.expires_at = 0.0

    def __reduce__(self):   # never pickled (Streamlit does not, but a cache or a copy must not either)
        raise TypeError("Login objects cannot be serialised")


# -------------------------------------------------------------- host keys ----
def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _known_hosts() -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    for path in (Path.home() / ".ssh" / "known_hosts", policy().get("known_hosts_file") or ""):
        if path and Path(path).is_file():
            try:
                keys.load(str(path))
            except (OSError, paramiko.SSHException):
                continue
    return keys


def _lookup_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


@dataclass
class HostKey:
    host: str
    port: int
    key_type: str = ""
    key_base64: str = field(default="", repr=False)
    fingerprint: str = ""
    status: str = ""        # known / new / CHANGED / unreachable
    error: str = ""


def scan_host_key(host: str, port: int, timeout: float) -> HostKey:
    """Fetch the server's host key without logging in, and compare it with known_hosts."""
    result = HostKey(host, port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            transport = paramiko.Transport(sock)
            try:
                transport.start_client(timeout=timeout)
                key = transport.get_remote_server_key()
            finally:
                transport.close()
    except (OSError, paramiko.SSHException, EOFError) as error:
        result.status, result.error = "unreachable", str(error) or error.__class__.__name__
        return result
    result.key_type, result.key_base64, result.fingerprint = key.get_name(), key.get_base64(), fingerprint(key)
    known = _known_hosts().lookup(_lookup_name(host, port))
    if not known or key.get_name() not in known:
        result.status = "new"
    else:
        result.status = "known" if known[key.get_name()] == key else "CHANGED"
    return result


def scan_host_keys(hosts: list[str], port: int, parallel: int = 10) -> list[HostKey]:
    timeout = float(policy()["connect_timeout_seconds"])
    with ThreadPoolExecutor(max_workers=max(1, min(parallel, len(hosts) or 1))) as pool:
        return list(pool.map(lambda h: scan_host_key(h, port, timeout), hosts))


# ------------------------------------------------------------------- runs ----
@dataclass
class Result:
    host: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    seconds: float = 0.0
    error: str = ""
    truncated: bool = False

    @property
    def status(self) -> str:
        if self.error:
            return "Error"
        return "OK" if self.exit_code == 0 else "Failed"


def _client(host: str, login: Login, trusted: dict[str, HostKey]) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    known = _known_hosts()
    name = _lookup_name(host, login.port)
    for key_type, key in (known.lookup(name) or {}).items():
        client.get_host_keys().add(name, key_type, key)
    accepted = trusted.get(host)
    if accepted and accepted.key_base64:
        key = paramiko.PKey.from_type_string(accepted.key_type, base64.b64decode(accepted.key_base64))
        client.get_host_keys().add(name, accepted.key_type, key)
    timeout = float(policy()["connect_timeout_seconds"])
    client.connect(host, port=login.port, username=login.username, password=login.password or None,
                   pkey=login.key(), allow_agent=False, look_for_keys=False, timeout=timeout,
                   banner_timeout=timeout, auth_timeout=timeout)
    return client


def check_login(host: str, login: Login, trusted: dict[str, HostKey]) -> Result:
    """Log in and out without running anything."""
    started = time.monotonic()
    try:
        _client(host, login, trusted).close()
        return Result(host, exit_code=0, seconds=round(time.monotonic() - started, 1))
    except Exception as error:   # noqa: BLE001 - every failure is reported per server
        return Result(host, error=_reason(error), seconds=round(time.monotonic() - started, 1))


def _reason(error: Exception) -> str:
    if isinstance(error, paramiko.AuthenticationException):
        return "Login refused: check the user name and password or key."
    if isinstance(error, paramiko.BadHostKeyException):
        return "The server's host key has CHANGED since it was recorded. Not connecting."
    if isinstance(error, paramiko.SSHException) and "not found in known_hosts" in str(error):
        return "Unknown host key: accept it for this session first."
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "No answer in time."
    return str(error) or error.__class__.__name__


def wrap(command: str, *, sudo: bool, windows: bool, stop_on_error: bool) -> str:
    """The command line sent to the server. Linux: one bash script, optionally under sudo."""
    if windows:
        return command
    script = ("set -e\n" if stop_on_error else "") + command
    if sudo:
        return f"sudo -S -p '' bash -c {shlex.quote(script)}"
    return f"bash -c {shlex.quote(script)}"


def run_on_host(host: str, command: str, login: Login, trusted: dict[str, HostKey], *, sudo: bool = False,
                windows: bool = False, stop_on_error: bool = True, timeout: float | None = None) -> Result:
    rules = policy()
    timeout = float(timeout or rules["command_timeout_seconds"])
    limit = int(rules["output_limit_kb"]) * 1024
    started = time.monotonic()
    result = Result(host)
    try:
        client = _client(host, login, trusted)
    except Exception as error:   # noqa: BLE001
        result.error, result.seconds = _reason(error), round(time.monotonic() - started, 1)
        return result
    try:
        channel = client.get_transport().open_session(timeout=timeout)
        channel.settimeout(timeout)
        channel.exec_command(wrap(command, sudo=sudo and not windows, windows=windows, stop_on_error=stop_on_error))
        if sudo and not windows:
            secret = login.sudo_password or login.password
            channel.sendall(((secret + "\n") if secret else "").encode())
        channel.shutdown_write()
        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                out += channel.recv(65536)
            if channel.recv_stderr_ready():
                err += channel.recv_stderr(65536)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            if time.monotonic() > deadline:
                result.error = f"Timed out after {int(timeout)} s; the command may still be running on the server."
                break
            time.sleep(0.05)
        if not result.error:
            result.exit_code = channel.recv_exit_status()
        result.truncated = len(out) > limit or len(err) > limit
        result.stdout = out[:limit].decode("utf-8", "replace")
        result.stderr = err[:limit].decode("utf-8", "replace")
    except Exception as error:   # noqa: BLE001
        result.error = _reason(error)
    finally:
        client.close()
        result.seconds = round(time.monotonic() - started, 1)
    return result


def run(hosts: list[str], command: str, login: Login, trusted: dict[str, HostKey], *, windows_hosts: set[str],
        sudo: bool = False, stop_on_error: bool = True, parallel: int = 5, timeout: float | None = None) -> list[Result]:
    login.touch()
    with ThreadPoolExecutor(max_workers=max(1, min(int(parallel), len(hosts) or 1))) as pool:
        return list(pool.map(lambda host: run_on_host(
            host, command, login, trusted, sudo=sudo, windows=host in windows_hosts, stop_on_error=stop_on_error,
            timeout=timeout), hosts))


def check_logins(hosts: list[str], login: Login, trusted: dict[str, HostKey], parallel: int = 10) -> list[Result]:
    with ThreadPoolExecutor(max_workers=max(1, min(parallel, len(hosts) or 1))) as pool:
        return list(pool.map(lambda host: check_login(host, login, trusted), hosts))


def audit(*, user: str, viewer: str, hosts: list[str], command: str, sudo: bool, results: list[Result],
          source: str) -> None:
    """One line per run. No passwords, keys or output."""
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    event = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ssh_user": user, "viewer": viewer,
        "source": source, "sudo": sudo, "command": command, "hosts": hosts,
        "exit_codes": {r.host: (r.exit_code if not r.error else r.error[:80]) for r in results},
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
