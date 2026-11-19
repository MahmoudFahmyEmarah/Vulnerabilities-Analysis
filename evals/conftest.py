"""Shared test setup: model-call logs from the tests go to a temporary folder, not the app's own log."""
from __future__ import annotations

import pytest

import settings
from observability import tracing


@pytest.fixture(autouse=True)
def _isolated_call_log(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(tracing, "LOG_FILE", tmp_path / "logs" / "llm_calls.jsonl")
