Write a remediation runbook for this failed MBSS control (Minimum Baseline Security Standard, checked by the Qualys policy compliance scanner).

{{scan_data}}

Notes on the fields:
- "expected_configuration" is what the baseline requires; "current_evidence" is what the scanner found on the server.
- "scanner_remediation" is the generic remediation text from the baseline. Turn it into concrete commands for the operating system in "os_family".
- Hardening changes can break running services (mount options, kernel parameters, SSH settings, user rights). Say what could be affected for a big-data node and how to test it.
- On Windows prefer Group Policy over local edits when the server is domain joined, and give the local equivalent as well.

Return a JSON object with exactly these keys:
- "summary": one or two sentences on what to change.
- "root_cause": one sentence on what is misconfigured.
- "prerequisites": list.
- "steps": list of {"title", "detail", "commands"}.
- "verification": list of commands or checks that show the control now passes.
- "rollback": list.
- "restart_required": "none", "service" or "host".
- "downtime_expected": true or false.
- "estimated_minutes_per_server": integer.
- "caveats": list.

Example of the shape (different finding, do not copy its content):
{{example}}
