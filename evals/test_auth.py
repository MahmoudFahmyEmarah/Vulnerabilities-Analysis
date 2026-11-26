"""Accounts: passwords, lock-out, and the rules that keep at least one admin."""
from __future__ import annotations

import json

import pytest

import settings
from tools import auth


def test_accounts_sign_in_lock_out_and_keep_an_admin(monkeypatch, tmp_path):
    monkeypatch.setattr(auth, "users_file", lambda: tmp_path / "users.json")
    monkeypatch.setattr(settings, "LOG_DIR", tmp_path)
    monkeypatch.setattr(auth, "AUDIT_FILE", tmp_path / "auth.jsonl")
    monkeypatch.setattr(auth, "_ROUNDS", 1000)   # fast hashing for the test
    monkeypatch.setattr(auth, "_failures", {})

    auth.add_user("Boss", auth.ADMIN, "correct horse battery", by="test")
    auth.add_user("owner1", auth.OWNER, "another long secret")
    stored = json.loads((tmp_path / "users.json").read_text())["users"]
    assert "correct horse battery" not in json.dumps(stored) and stored["boss"]["password"].startswith("pbkdf2_sha256$")
    assert auth.sign_in(" BOSS ", "correct horse battery") == {"name": "boss", "role": auth.ADMIN}

    with pytest.raises(auth.AuthError, match="at least"):
        auth.add_user("short", auth.OWNER, "tiny")
    for _ in range(int(auth.config()["max_failures"])):
        with pytest.raises(auth.AuthError, match="Wrong user name or password"):
            auth.sign_in("owner1", "not it")
    with pytest.raises(auth.AuthError, match="Too many"):
        auth.sign_in("owner1", "another long secret")     # locked even with the right password
    auth.set_password("owner1", "a brand new secret", by="boss")    # an admin reset clears the lock
    assert auth.sign_in("owner1", "a brand new secret")["role"] == auth.OWNER

    with pytest.raises(auth.AuthError, match="last admin"):
        auth.set_role("boss", auth.OWNER, by="owner1")
    with pytest.raises(auth.AuthError, match="own account"):
        auth.remove_user("boss", by="boss")
    auth.set_role("owner1", auth.ADMIN, by="boss")
    auth.remove_user("boss", by="owner1")
    assert set(auth.load_users()) == {"owner1"}
    assert "a brand new secret" not in (tmp_path / "auth.jsonl").read_text()
