"""Model gateway and the base class every agent inherits.

The gateway is LangChain's ChatOpenAI pointed at a self-hosted, OpenAI-compatible
endpoint. Only the endpoint is required (LLM_BASE_URL in .env); the model name is
discovered from the endpoint when it is not set.

Every agent follows the same loop: render prompt -> call model -> parse JSON ->
validate against its schema -> retry once with the error if validation fails.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, ValidationError

import settings
from observability import tracing


class AgentError(RuntimeError):
    """The model could not be reached or did not return a usable answer."""


@dataclass(frozen=True)
class LLMSettings:
    base_url: str
    api_key: str
    model: str
    temperature: float
    max_tokens: int
    timeout: int
    json_mode: bool
    max_retries: int
    preferred_models: tuple[str, ...]


def llm_settings() -> LLMSettings:
    # .env is re-read on every call so changes saved on the Settings page apply at once.
    # A value set in .env wins; a blank or missing one falls back to the process environment
    # (for example variables set on a CML Application), then to config.yaml.
    saved = dotenv_values(settings.ENV_FILE) if settings.ENV_FILE.exists() else {}

    def value(name: str) -> str:
        return (saved.get(name) or os.getenv(name) or "").strip()

    config = settings.load_config().get("llm", {})
    return LLMSettings(
        base_url=value("LLM_BASE_URL").rstrip("/"),
        api_key=value("LLM_API_KEY") or "not-needed",
        model=value("LLM_MODEL") or str(config.get("model") or "").strip(),
        temperature=float(config.get("temperature", 0.2)),
        max_tokens=int(config.get("max_tokens", 3000)),
        timeout=int(config.get("timeout_seconds", 180)),
        json_mode=bool(config.get("json_mode", True)),
        max_retries=int(config.get("max_retries", 1)),
        preferred_models=tuple(config.get("preferred_models") or ()),
    )


def is_configured() -> bool:
    return bool(llm_settings().base_url)


_model_cache: dict[str, list[str]] = {}


def list_models(config: LLMSettings | None = None, refresh: bool = False) -> list[str]:
    """Ask the endpoint which models it serves (GET /models)."""
    config = config or llm_settings()
    if not config.base_url:
        raise AgentError("No endpoint is configured. Set LLM_BASE_URL in .env or on the Settings page.")
    if refresh or config.base_url not in _model_cache:
        from openai import OpenAI

        try:
            client = OpenAI(base_url=config.base_url, api_key=config.api_key, timeout=15, max_retries=0)
            _model_cache[config.base_url] = [model.id for model in client.models.list()]
        except Exception as error:  # noqa: BLE001
            raise AgentError(f"Could not reach {config.base_url}: {error}") from error
    return _model_cache[config.base_url]


def resolve_model(config: LLMSettings | None = None) -> str:
    """Configured model, else the preferred one the endpoint serves, else the first it serves."""
    config = config or llm_settings()
    if config.model:
        return config.model
    served = list_models(config)
    if not served:
        raise AgentError(f"{config.base_url} serves no models.")
    for wanted in config.preferred_models:
        for name in served:
            if wanted.lower() in name.lower():
                return name
    return served[0]


def extract_json(text: str) -> dict[str, Any]:
    """Pull the JSON object out of a model answer (tolerates reasoning tags and code fences)."""
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL)
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("the answer contains no JSON object")
    return json.loads(text[start:end + 1])


def render(template: str, **variables: Any) -> str:
    """Fill {{name}} placeholders. Plain replacement, so braces in scan text are harmless."""
    for name, value in variables.items():
        template = template.replace("{{" + name + "}}", str(value))
    return template


def read_prompt(relative: str) -> str:
    return (settings.PROMPTS_DIR / relative).read_text(encoding="utf-8")


def few_shot(name: str) -> str:
    examples = yaml.safe_load(read_prompt("few_shots.yaml")) or {}
    return json.dumps(examples[name], indent=2, ensure_ascii=False)


def _text_of(message: Any) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    parts = [block.get("text", "") if isinstance(block, dict) else str(block) for block in content]
    return "".join(parts)


class BaseAgent:
    """Subclasses set ``name``, ``system_prompt``, ``template`` and ``schema``."""

    name = "agent"
    system_prompt = ""   # file under prompts/system/
    template = ""        # file under prompts/templates/
    schema: type[BaseModel] = BaseModel

    def __init__(self, config: LLMSettings | None = None):
        self.config = config or llm_settings()

    def _chat(self, model: str, json_mode: bool):
        from langchain_openai import ChatOpenAI

        options: dict[str, Any] = {}
        if json_mode:
            options["model_kwargs"] = {"response_format": {"type": "json_object"}}
        return ChatOpenAI(
            base_url=self.config.base_url, api_key=self.config.api_key, model=model,
            temperature=self.config.temperature, max_tokens=self.config.max_tokens,
            timeout=self.config.timeout, max_retries=1, **options,
        )

    def _invoke(self, model: str, messages: list[Any]) -> Any:
        try:
            return self._chat(model, self.config.json_mode).invoke(messages)
        except Exception as error:  # noqa: BLE001
            # Some servers reject response_format; retry once without it.
            if self.config.json_mode and getattr(error, "status_code", None) in (400, 422):
                return self._chat(model, False).invoke(messages)
            raise

    def run(self, template: str | None = None, **variables: Any) -> tuple[BaseModel, dict[str, Any]]:
        """Call the model and return (validated answer, call details)."""
        from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

        if not self.config.base_url:
            raise AgentError("No endpoint is configured. Set LLM_BASE_URL in .env or on the Settings page.")
        model = resolve_model(self.config)
        system = read_prompt(f"system/{self.system_prompt}")
        user = render(read_prompt(f"templates/{template or self.template}"), **variables)
        messages: list[Any] = [SystemMessage(system), HumanMessage(user)]

        started = time.perf_counter()
        trace: dict[str, Any] = {"agent": self.name, "model": model, "prompt_chars": len(system) + len(user),
                                 "attempts": 0, "ok": False}
        problem = ""
        try:
            for _ in range(self.config.max_retries + 1):
                trace["attempts"] += 1
                reply = self._invoke(model, messages)
                answer = _text_of(reply)
                usage = getattr(reply, "usage_metadata", None) or {}
                trace["input_tokens"] = trace.get("input_tokens", 0) + int(usage.get("input_tokens", 0) or 0)
                trace["output_tokens"] = trace.get("output_tokens", 0) + int(usage.get("output_tokens", 0) or 0)
                trace["answer_chars"] = len(answer)
                try:
                    parsed = self.schema.model_validate(extract_json(answer))
                    trace["ok"] = True
                    return parsed, {"model": model, "attempts": trace["attempts"],
                                    "seconds": round(time.perf_counter() - started, 1)}
                except (ValueError, ValidationError) as error:
                    problem = str(error)[:600]
                    messages += [AIMessage(answer), HumanMessage(
                        "That answer could not be used: " + problem +
                        "\nReply again with ONLY one valid JSON object in the required shape.")]
            raise AgentError(f"The model did not return valid JSON after {trace['attempts']} attempts: {problem}")
        except AgentError as error:
            trace["error"] = str(error)[:300]
            raise
        except Exception as error:  # noqa: BLE001 - network, auth, timeout ...
            trace["error"] = f"{type(error).__name__}: {error}"[:300]
            raise AgentError(f"Model call failed ({type(error).__name__}): {error}") from error
        finally:
            trace["seconds"] = round(time.perf_counter() - started, 2)
            tracing.record(trace)
