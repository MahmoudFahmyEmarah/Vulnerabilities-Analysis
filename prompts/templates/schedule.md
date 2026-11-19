Plan the fix schedule for one application.

Policy:
{{policy}}

Application context (servers per environment, pending work, SLA pressure):
{{context}}

Available change windows (choose by slot_id; "minutes" is the window length):
{{slots}}

Rule-based draft you may improve (it already obeys the policy):
{{draft}}

Return a JSON object with exactly these keys:
- "summary": two or three sentences on the approach and why.
- "risks": list of risks or assumptions an approver should know.
- "waves": list of waves, each with:
  - "name": short name, for example "Development", "Production canary", "Production wave 2"
  - "environment": "Development" or "Production"
  - "slot_id": one slot_id from the list above
  - "servers": list of server names from the context
  - "work_items": list of what is done in this wave
  - "estimated_minutes": integer, total for the wave
  - "downtime_expected": true or false
  - "pre_checks": list
  - "post_checks": list
  - "rollback": one or two sentences
  - "rationale": one sentence on why this window and this grouping

Example of the shape (do not copy its content):
{{example}}
