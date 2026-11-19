Write an onboarding runbook to close a cybersecurity control gap on the servers of one application.

{{scan_data}}

About the controls:
- Antivirus and EDR: an endpoint agent must be installed, running and reporting to its console.
- SIEM: the server must forward its logs to the central SIEM.
- Vulnerability scan: the scanner must reach the server and log in ("Scanned without Authentication" and "Not Reachable" are gaps).
- Qualys agent: the Qualys Cloud Agent must be installed and checking in.
- PAM: administrative access must go through the privileged access management platform.

You do not know this company's internal console addresses, activation keys, installer locations or request process. Do not invent them. Write the technical steps on the server itself (install, configure, open connectivity, start, verify) and list in "prerequisites" what the engineer must obtain from the security team.

Return a JSON object with exactly these keys:
- "summary": one or two sentences.
- "root_cause": the most likely reasons for this gap given the status breakdown.
- "prerequisites": list.
- "steps": list of {"title", "detail", "commands"}.
- "verification": list.
- "rollback": list.
- "restart_required": "none", "service" or "host".
- "downtime_expected": true or false.
- "estimated_minutes_per_server": integer.
- "caveats": list.

Example of the shape (different finding, do not copy its content):
{{example}}
