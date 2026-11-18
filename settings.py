"""Central configuration: paths, config.yaml, guardrails/policies.yaml and .env."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
CONFIG_FILE = ROOT / "config.yaml"
POLICIES_FILE = ROOT / "guardrails" / "policies.yaml"
PROMPTS_DIR = ROOT / "prompts"
KB_FILE = ROOT / "memory" / "store" / "knowledge_base.sqlite"
LOG_DIR = ROOT / "observability" / "logs"

load_dotenv(ENV_FILE)

_yaml_cache: dict[Path, tuple[int, dict]] = {}


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file, re-reading only when it changes on disk."""
    mtime = path.stat().st_mtime_ns
    cached = _yaml_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    _yaml_cache[path] = (mtime, data)
    return data


def load_config() -> dict[str, Any]:
    return _read_yaml(CONFIG_FILE)


def load_policies() -> dict[str, Any]:
    return _read_yaml(POLICIES_FILE)


def resolve(relative: str) -> Path:
    """Turn a path from config.yaml into an absolute path under the project."""
    path = Path(relative)
    return path if path.is_absolute() else ROOT / path


def data_dir() -> Path:
    return resolve(os.getenv("DATA_DIR") or load_config()["app"]["data_dir"])


def cache_dir() -> Path:
    path = resolve(load_config()["app"]["cache_dir"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def server_list_file() -> Path:
    return resolve(load_config()["app"]["server_list"])


def inventory_file() -> Path | None:
    relative = load_config()["app"].get("ai_inventory")
    return resolve(relative) if relative else None


def overrides_file() -> Path:
    return resolve(load_config()["app"]["environment_overrides"])
