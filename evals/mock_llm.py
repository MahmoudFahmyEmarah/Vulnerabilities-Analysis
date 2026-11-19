"""A tiny OpenAI-compatible server for tests and offline demos. It is NOT a model.

It answers GET /v1/models and POST /v1/chat/completions with canned JSON so the
whole pipeline (gateway, parsing, guardrails, knowledge base, UI) can be exercised
without the real endpoint.

    python -m evals.mock_llm            # serves http://127.0.0.1:8790/v1
    python -m evals.mock_llm 9000       # or another port
    LLM_BASE_URL=http://127.0.0.1:8790/v1 in .env to point the app at it

Set MOCK_LLM_BREAK_POLICY=1 to make it return a schedule that violates the change
policy (production in a development window) and watch the guardrail correct it.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_NAME = "mock-gpt-oss-120b"
requests_seen: list[dict] = []


def _remediation() -> dict:
    return {
        "summary": "MOCK ANSWER — update the affected package to the fixed version named in the advisory.",
        "root_cause": "The installed version is older than the fixed version.",
        "prerequisites": ["Root access", "Access to the package repository"],
        "steps": [
            {"title": "Check the installed version", "detail": "Confirm the node is affected.",
             "commands": ["rpm -qa | grep -i <package>"]},
            {"title": "Apply the update", "detail": "Update only the affected package.",
             "commands": ["dnf update -y <package>"]},
        ],
        "verification": ["rpm -q <package>"],
        "rollback": ["dnf history undo last -y"],
        "restart_required": "service",
        "downtime_expected": False,
        "estimated_minutes_per_server": 15,
        "caveats": ["This text comes from the mock server, not from a model."],
    }


def _schedule(prompt: str) -> dict:
    match = re.search(r"obeys the policy\):\n(\[.*?\])\n\nReturn a JSON object", prompt, re.DOTALL)
    waves = json.loads(match.group(1)) if match else []
    for wave in waves:
        wave.update({"downtime_expected": True, "pre_checks": ["Cluster healthy"], "post_checks": ["Re-scan"],
                     "rollback": "Undo the change.", "rationale": "MOCK ANSWER — kept the draft grouping."})
    if os.getenv("MOCK_LLM_BREAK_POLICY") == "1":
        dev_slot = re.search(r'"slot_id": "(D-\d+)"', prompt)
        for wave in waves:
            if wave["environment"] == "Production" and dev_slot:
                wave["slot_id"] = dev_slot.group(1)   # production in working hours: must be corrected
    return {"summary": "MOCK ANSWER — development first, then production outside working hours.",
            "risks": ["This plan comes from the mock server, not from a model."], "waves": waves}


def _labels(prompt: str) -> dict:
    labels = []
    for number, title in re.findall(r"^(\d+)\. (.+)$", prompt, re.MULTILINE):
        is_os = bool(re.search(r"kernel|windows|red hat|ssh|permission", title, re.IGNORECASE))
        labels.append({"id": int(number), "topic": "OS Issue" if is_os else "Application Issue"})
    return {"labels": labels}


def answer_for(prompt: str) -> dict:
    if "Plan the fix schedule" in prompt:
        return _schedule(prompt)
    if "Label each finding title" in prompt:
        return _labels(prompt)
    return _remediation()


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            self._send({"object": "list", "data": [{"id": MODEL_NAME, "object": "model", "created": 0,
                                                    "owned_by": "mock"}]})
        else:
            self._send({"error": {"message": "not found"}}, 404)

    def do_POST(self) -> None:  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        requests_seen.append({"path": self.path, "keys": sorted(body.keys())})
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send({"error": {"message": f"unsupported path {self.path}"}}, 404)
            return
        prompt = "\n".join(str(m.get("content", "")) for m in body.get("messages", []) if m.get("role") == "user")
        content = json.dumps(answer_for(prompt))
        self._send({
            "id": "mock-1", "object": "chat.completion", "created": 0, "model": body.get("model", MODEL_NAME),
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": len(prompt) // 4, "completion_tokens": len(content) // 4,
                      "total_tokens": (len(prompt) + len(content)) // 4},
        })

    def log_message(self, *args) -> None:  # keep test output quiet
        pass


def start(port: int = 8790) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8790
    print(f"Mock model endpoint on http://127.0.0.1:{port}/v1 (model '{MODEL_NAME}'). Ctrl+C to stop.", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
