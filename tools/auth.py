"""Dashboard accounts: two roles, admin and platform owner, kept in a local JSON file.

Passwords are never stored: only a salted PBKDF2-SHA256 hash (600,000 rounds). The file
(config.yaml -> auth.users_file, by default memory/store/users.json) is git-ignored and is not
part of the CML zip. Repeated wrong passwords lock the account for a while.

Create the first admin from a terminal (the password is asked for and not echoed):

    python -m tools.auth add <name> --role admin

Other commands: list, remove <name>, password <name>, role <name> admin|owner.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import settings

ADMIN, OWNER = "admin", "owner"
ROLES = {ADMIN: "Admin", OWNER: "Platform owner"}
_ROUNDS = 600_000
_NAME = re.compile(r"^[a-z0-9][a-z0-9._@-]{1,63}$")
_LOCK = threading.Lock()
_failures: dict[str, list[float]] = {}          # name -> times of recent wrong passwords (this process)
AUDIT_FILE = settings.LOG_DIR / "auth.jsonl"


class AuthError(ValueError):
    """A user-facing reason an account change or sign-in was refused."""


def config() -> dict[str, Any]:
    defaults = {"enabled": True, "users_file": "memory/store/users.json", "session_hours": 12,
                "min_password_length": 12, "max_failures": 5, "lockout_minutes": 15}
    return {**defaults, **(settings.load_config().get("auth") or {})}


def enabled() -> bool:
    return bool(config().get("enabled", True))


def users_file() -> Path:
    return settings.resolve(str(config()["users_file"]))


# ------------------------------------------------------------------ hashing ----
def hash_password(password: str, rounds: int | None = None) -> str:
    rounds = rounds or _ROUNDS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt, digest = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.b64decode(salt), int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


_DUMMY = hash_password(secrets.token_urlsafe(16))   # unknown names take as long as known ones


# -------------------------------------------------------------------- store ----
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_users() -> dict[str, dict[str, Any]]:
    path = users_file()
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return (json.load(handle) or {}).get("users", {})


def _save(users: dict[str, dict[str, Any]]) -> None:
    path = users_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"users": users}, indent=2, ensure_ascii=False), encoding="utf-8")
    if os.name == "posix":
        os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def audit(event: str, name: str, by: str = "", **details: Any) -> None:
    """One line per sign-in or account change. Never a password."""
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"time": _now(), "event": event, "user": name, "by": by, **details}) + "\n")


def normalise(name: str) -> str:
    return str(name or "").strip().lower()


def _check_name(name: str) -> str:
    name = normalise(name)
    if not _NAME.match(name):
        raise AuthError("User names are 2–64 characters: letters, digits, dot, dash, underscore or @.")
    return name


def check_new_password(password: str, name: str = "") -> None:
    minimum = int(config()["min_password_length"])
    if len(password or "") < minimum:
        raise AuthError(f"Use at least {minimum} characters.")
    if name and normalise(name) in password.lower():
        raise AuthError("The password must not contain the user name.")


def _admins(users: dict[str, dict[str, Any]]) -> list[str]:
    return [name for name, user in users.items() if user.get("role") == ADMIN]


def add_user(name: str, role: str, password: str, by: str = "") -> None:
    name = _check_name(name)
    if role not in ROLES:
        raise AuthError(f"Role must be one of: {', '.join(ROLES)}.")
    check_new_password(password, name)
    with _LOCK:
        users = load_users()
        if name in users:
            raise AuthError(f"'{name}' already exists.")
        users[name] = {"role": role, "password": hash_password(password), "created": _now(), "created_by": by,
                       "last_login": ""}
        _save(users)
    audit("user added", name, by, role=role)


def remove_user(name: str, by: str = "") -> None:
    name = normalise(name)
    with _LOCK:
        users = load_users()
        if name not in users:
            raise AuthError(f"'{name}' does not exist.")
        if name == normalise(by):
            raise AuthError("You cannot remove your own account.")
        if users[name].get("role") == ADMIN and len(_admins(users)) == 1:
            raise AuthError("This is the last admin; add another admin first.")
        del users[name]
        _save(users)
    audit("user removed", name, by)


def set_role(name: str, role: str, by: str = "") -> None:
    name = normalise(name)
    if role not in ROLES:
        raise AuthError(f"Role must be one of: {', '.join(ROLES)}.")
    with _LOCK:
        users = load_users()
        if name not in users:
            raise AuthError(f"'{name}' does not exist.")
        if users[name].get("role") == ADMIN and role != ADMIN:
            if name == normalise(by):
                raise AuthError("You cannot take the admin role from yourself.")
            if len(_admins(users)) == 1:
                raise AuthError("This is the last admin; add another admin first.")
        users[name]["role"] = role
        _save(users)
    audit("role changed", name, by, role=role)


def set_password(name: str, password: str, by: str = "") -> None:
    name = normalise(name)
    check_new_password(password, name)
    with _LOCK:
        users = load_users()
        if name not in users:
            raise AuthError(f"'{name}' does not exist.")
        users[name]["password"] = hash_password(password)
        _save(users)
    _failures.pop(name, None)
    audit("password changed", name, by)


# ------------------------------------------------------------------ sign-in ----
def locked_minutes(name: str) -> int:
    """Minutes left on a lock-out after too many wrong passwords (0 = not locked)."""
    rules = config()
    window = int(rules["lockout_minutes"]) * 60
    recent = [t for t in _failures.get(normalise(name), []) if time.time() - t < window]
    if len(recent) < int(rules["max_failures"]):
        return 0
    return max(1, int((recent[-1] + window - time.time()) // 60) + 1)


def sign_in(name: str, password: str) -> dict[str, Any]:
    """Check a user name and password. Returns {"name", "role"} or raises AuthError (a generic message)."""
    name = normalise(name)
    if locked_minutes(name):
        audit("sign-in refused (locked)", name)
        raise AuthError(f"Too many wrong passwords. Try again in {locked_minutes(name)} minute(s).")
    user = load_users().get(name)
    ok = check_password(password or "", user["password"] if user else _DUMMY) and user is not None
    if not ok:
        window = int(config()["lockout_minutes"]) * 60
        with _LOCK:
            _failures[name] = [t for t in _failures.get(name, []) if time.time() - t < window] + [time.time()]
        audit("sign-in failed", name)
        raise AuthError("Wrong user name or password.")
    _failures.pop(name, None)
    with _LOCK:
        users = load_users()
        if name in users:
            users[name]["last_login"] = _now()
            _save(users)
    audit("signed in", name)
    return {"name": name, "role": user["role"]}


# ---------------------------------------------------------------------- CLI ----
def _ask_password(name: str) -> str:
    first = getpass.getpass(f"Password for {name}: ")
    if first != getpass.getpass("Repeat it: "):
        raise AuthError("The two passwords differ.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.auth", description="Manage dashboard accounts.")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="add an account (asks for the password)")
    add.add_argument("name")
    add.add_argument("--role", choices=list(ROLES), default=OWNER)
    commands.add_parser("list", help="list accounts")
    remove = commands.add_parser("remove", help="remove an account")
    remove.add_argument("name")
    password = commands.add_parser("password", help="set a new password (asks for it)")
    password.add_argument("name")
    role = commands.add_parser("role", help="change an account's role")
    role.add_argument("name")
    role.add_argument("role", choices=list(ROLES))
    args = parser.parse_args(argv)
    try:
        if args.command == "add":
            add_user(args.name, args.role, _ask_password(normalise(args.name)), by="command line")
            print(f"Added {normalise(args.name)} ({ROLES[args.role]}) to {users_file()}.")
        elif args.command == "list":
            users = load_users()
            if not users:
                print(f"No accounts yet in {users_file()}.")
            for name, user in sorted(users.items()):
                print(f"{name:30} {ROLES.get(user.get('role'), user.get('role')):15} last sign-in: {user.get('last_login') or 'never'}")
        elif args.command == "remove":
            remove_user(args.name, by="command line")
            print(f"Removed {normalise(args.name)}.")
        elif args.command == "password":
            set_password(args.name, _ask_password(normalise(args.name)), by="command line")
            print("Password changed.")
        elif args.command == "role":
            set_role(args.name, args.role, by="command line")
            print(f"{normalise(args.name)} is now {ROLES[args.role]}.")
    except AuthError as error:
        print(f"Not done: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
