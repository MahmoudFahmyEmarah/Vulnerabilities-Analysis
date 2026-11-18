# Prompt changelog

Prompts are code. Record every change here with the date and the reason, so a bad change can be rolled back.

## 2026-11-18 — v1
- First version for self-hosted models (gpt-oss-120b / Qwen) behind an OpenAI-compatible endpoint.
- `system/remediation.md`: runbook persona; scan text is treated as data; no disabling of security controls; rollback and verification are mandatory.
- `system/scheduler.md`: the model picks change windows by `slot_id` only and never writes dates.
- `system/classifier.md`: OS / application labelling for titles the rules cannot place.
- Templates for vulnerability, MBSS and CS-control findings, and for the fix schedule.
- `few_shots.yaml`: one remediation example and one schedule example to lock the JSON shape.
