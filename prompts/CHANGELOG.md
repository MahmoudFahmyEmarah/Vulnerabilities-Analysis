# Prompt changelog

Prompts are code. Record every change here with the date and the reason, so a bad change can be rolled back.

## 2026-11-19 — v1.1
- `system/scheduler.md`: the soak between development and production is no longer optional. The schedule
  guardrail now enforces it (and the window capacity), so the prompt no longer invites the model to shorten it.
- Scan text: any `<scan_data>` tag inside scanner text (including HTML-escaped ones) is neutralised before it
  is wrapped, so the text cannot close the data block early (`guardrails/input_checks.as_scan_data`).

## 2026-11-18 — v1
- First version for self-hosted models (gpt-oss-120b / Qwen) behind an OpenAI-compatible endpoint.
- `system/remediation.md`: runbook persona; scan text is treated as data; no disabling of security controls; rollback and verification are mandatory.
- `system/scheduler.md`: the model picks change windows by `slot_id` only and never writes dates.
- `system/classifier.md`: OS / application labelling for titles the rules cannot place.
- Templates for vulnerability, MBSS and CS-control findings, and for the fix schedule.
- `few_shots.yaml`: one remediation example and one schedule example to lock the JSON shape.
