# Security Posture Dashboard

One place to track three security checks for the platform's servers, with AI help to fix them:

- **Vulnerabilities** — open Qualys findings, SLA status, split into OS issues and application issues
- **MBSS** — failed Minimum Baseline Security Standard controls
- **CS Controls** — coverage of antivirus, EDR, SIEM, vulnerability scanning, the Qualys agent and PAM
- **Trends** — what changed since last week (new, fixed, still open, not rescanned) and the weekly trend
- **Fix Schedule** — a per-application plan in 2 to 4 waves: development first, production only outside Saudi
  working hours
- **AI recommendations** — step-by-step fixes from a self-hosted model, stored and reused, downloadable as an
  Ansible playbook
- **Run on servers** — sign in over SSH for the browser session and run one command on one or many servers
- **Email report** — email the numbers and main findings of one platform, several applications or all of them,
  with the Excel export attached
- **Excel export** — *Export to Excel* on the Overview page: one workbook for the sidebar scope with a summary and
  charts, one row per application, and every open finding, failed MBSS check and server with a CS gap

## Run it locally

Step by step for another machine or CML, and every setting in one place: [DEPLOYMENT.md](DEPLOYMENT.md).

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m streamlit run app.py
```

Python 3.11 or newer is required (pandas 3). On Linux or macOS use `.venv/bin/python`.

Put the three Excel reports in `latest_Data/` (or upload them on the Settings page). The newest file of each
kind is used. The first read of a new file takes about half a minute; after that it is cached in `.cache/`.

Uploading on the Settings page checks each file before the pages see it: it shows the report type, the date
found in the file and which week the file will join, refuses files that are not one of the three reports, and
lets you change the week before saving. *Report weeks* on the same page moves a file that is already there to
another week. Those choices are kept in `latest_Data/report_dates.json` with each file's size, so they travel
with a copy of the folder and are dropped when a different file of the same name replaces one.

Keep last week's files next to this week's: the **Trends** page compares two weeks and plots every week present.
A file's week comes from its data (latest *Last Scan Date Time* or *Evaluation Date*), not from when it was
copied; the CS report has no date column, so it uses the date the workbook was saved (correct it under
*Report weeks* on the Settings page when it was saved days after the scans). Files dated within three
days of each other form one weekly set, and a second file of the same kind starts the next set, so two weekly
reports are never merged whichever weekday their scans ended on. Because the reports only
list open findings, a finding that disappears counts as *Fixed* only if its server is still in this week's
reports; otherwise it is *Not rescanned*. The rules live in `tools/history.py`.

## Connect the model

Only the endpoint is needed. Any OpenAI-compatible server works (vLLM, Ollama, TGI, LiteLLM).

- On the **Settings** page: enter the endpoint, press *Test connection*, then *Save*; or
- in `.env` (copy `.env.example`): `LLM_BASE_URL=http://llm-host:8000/v1`; or
- as an environment variable `LLM_BASE_URL` (used when `.env` has no value).

The model name is read from the endpoint. When it serves several, `gpt-oss-120b` is preferred, then Qwen
(`config.yaml` → `llm.preferred_models`). Set `LLM_MODEL` to force one.

The endpoint applies to every user of the app, so on a CML Application the Settings page shows it read-only
and the environment variables decide. `MODEL_SETTINGS_EDITABLE=1` allows changes from the page again;
`MODEL_SETTINGS_EDITABLE=0` locks the page anywhere. A saved API key is never shown on the page.

Without an endpoint everything except the AI buttons works, and the Fix Schedule shows its rule-based draft.

## Host it as a CML Application

No Dockerfile is needed; CML runs the app in one of its ML Runtimes.

1. Create a CML project from this repository (or upload the folder). Use a **Python 3.11+** runtime.
2. Open a session and install the libraries once: `pip install -r requirements.txt`
3. Copy the report files into `latest_Data/` in the project (or upload them later on the Settings page).
4. **Applications → New Application**
   - Script: `cml_app.py`
   - Environment variable: `LLM_BASE_URL` = your model endpoint (optional: `LLM_MODEL`, `LLM_API_KEY`)
   - Resource profile: 2 vCPU / 8 GB is enough for the current report sizes
5. Start it and open the application link.

Check before going live:

- **Access.** The app has no login of its own and shows server names and IPs. Keep the application restricted
  to authenticated CML users.
- **Network.** The application pod must reach the model endpoint and, for step 2, PyPI or your package mirror.
  *Run on servers* also needs SSH (port 22) from the pod to the servers, and *Email report* needs the SMTP relay.
  Without them those two pages still load; the playbook and `.eml` downloads work everywhere.
- **Uploads.** If uploading a report on the Settings page fails with a 403 behind the CML proxy, add the
  environment variables `STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false` and `STREAMLIT_SERVER_ENABLE_CORS=false`
  to the application, or copy the files into `latest_Data/` instead.
- **Shared state.** The knowledge base (`memory/store/knowledge_base.sqlite`), the environment mapping and the
  cache live in the project folder, so all users of the application share them. SQLite is fine for a small
  team; it is not built for heavy concurrent writes. On CML the project folder is often network storage,
  where SQLite's file locking is unreliable: keep a copy of `memory/store/` if the stored recommendations matter.

`cml_app.py` listens on `127.0.0.1:$CDSW_APP_PORT`, which is what CML expects.

## Things to configure

| What | Where |
|---|---|
| Data folder, team name, SLA days, model options | `config.yaml` |
| Working days and hours, production windows, holiday freeze, soak time, canary size, waves | `guardrails/policies.yaml` |
| Run on servers: session length, time-outs, servers per run, known_hosts | `guardrails/policies.yaml` → `remote_run` |
| Email relay (`SMTP_*`), subject, allowed recipient domains | `.env` / environment, `config.yaml` → `email` |
| Which servers are production or development | Settings page → *Environment mapping* (saved to `reference/environment_overrides.csv`) |
| AI Platforms Inventory file and platform names | `config.yaml` → `app.ai_inventory`, `app.ai_inventory_names` |
| OS / application rules | `tools/classifier.py`, checked by `evals/golden_set.jsonl` |
| Prompts | `prompts/` (log changes in `prompts/CHANGELOG.md`) |

How the environment of a server is decided, strongest first: the override file, the AI Platforms Inventory,
the application name in the latest reports (Prod / DR / NonProd / Dev ...), then the team server list
(`MS_All_servers.xlsx`). If nothing is known, the server is treated as **production**.

### AI Platforms Inventory (reference for AI servers)

Put the inventory workbook in `reference/` and point `config.yaml` → `app.ai_inventory` at it. For every server
it lists:

- its **platform name** replaces the application name from the reports (the report's label stays visible as
  *Report Application*);
- its **environment** (from the Environment column, or the sheet name such as "Dev-..." / "... - Prod") is used;
- its **role** and **cluster** are shown next to the server.

`app.ai_inventory_names` renames sheets to application names. By default the development lake (*Advance*) and the
production lake (*Accelerate*) are both "AI Data Lake", so they are scheduled together: development first.
*All AI platforms* at the top of the sidebar's Applications filter picks every platform in the inventory at
once, and can be combined with other applications.
The Overview page lists inventory servers that appear in none of the reports. Only IP, host name, platform,
role, cluster, project, environment and status are read from the workbook; licence keys and credentials in it
are ignored. The workbook itself is not committed (`*.xlsx` is in `.gitignore`).

## How the fix schedule stays safe

A **wave** is one group of servers changed together, so one change to approve and run. The Fix Schedule page
offers three choices (`guardrails/policies.yaml` → `scheduling.waves`):

- **One per environment** (the default): one development wave, then one production wave;
- **Automatic**: production also gets a small first wave (a canary, `canary_fraction` of its servers) when it has
  more than `automatic_split_production_above` servers;
- **Custom**: pick the waves per environment, at least one each and **4 at most** in total (`max_total`).

A wave whose servers do not fit in one change window continues in the next free windows of its environment;
the timeline shows one row per wave and one bar per window, and the CSV has one row per window.

The model never writes dates. It picks the window each wave starts in by id, from a list the Saudi calendar
produces, and `guardrails/output_checks.enforce_schedule` re-checks every wave: extra waves are merged, a
production window that is not valid is replaced, unknown servers are dropped and forgotten servers are added to
the last wave of their environment. The guardrail works out each window's workload itself (minutes per server,
servers in parallel), so no window holds more work than it has time for, and production starts only after
development has finished and soaked. A weekend day that falls inside a holiday break (for example the Saturday
between Eid and its observed day off) is frozen like the holiday itself. Eid dates in the holiday calendar are
astronomical estimates; correct them with `extra_dates` / `remove_dates` in `guardrails/policies.yaml`.

*Download Ansible inventory* on the Fix Schedule page writes one group per wave (`wave_1`, ...) and per window
(`wave_1_window_2`, ...), so a finding's playbook can be run one wave at a time.

## Ansible playbooks

Every AI recommendation has *Download Ansible playbook*: a zip with `playbook.yml` (the steps as tasks, the
verification commands as tasks that change nothing, and rollback tasks that only run with `--tags rollback`)
and `inventory.ini` (the affected servers in `development` / `production` and `linux` / `windows` groups).
The play targets `development` unless you pass `-e target=production` (or `-e target=wave_1` with the schedule's
inventory), works one server at a time when a restart is needed, and stops when a host fails. Commands the
guardrail flags as risky, and commands that still hold a placeholder such as `<package>`, are not turned into
tasks; they are listed at the end of the playbook as comments. No credentials are written to either file. The
dashboard does not run Ansible itself: run the playbook from your Ansible control node.

## Run on servers

The *Run on servers* page runs one command, as one script, on one or many servers over SSH:

1. pick the servers (those in the sidebar scope; *Run on servers…* under an AI recommendation fills in its
   commands and the affected servers);
2. sign in with a user name and a password or a pasted private key, plus an optional sudo password;
3. accept any new host key after comparing its fingerprint (for this session only; a changed key is refused);
4. run, optionally with sudo, *set -e* and a time-out. Results show the exit code and output per server.

The credentials stay in the browser session's memory only: they are never written to disk, logged or sent to the
model, and they are forgotten after `remote_run.session_minutes` (30) minutes without use, on *Disconnect*, or
when the page is closed. Commands the guardrail flags as risky, or that still hold a placeholder, are refused.
Production servers need a confirmation, with a warning during Saudi working hours. Every run adds a line to
`observability/logs/remote_runs.jsonl`: who, which servers, the command and the exit codes, never passwords or
output. Only servers in the reports can be picked unless `remote_run.allow_other_hosts` is true. Windows servers
need OpenSSH; the command then runs in their default shell without sudo.

## Email report

The *Email report* page emails the posture of one platform, several applications or all of them. The email
has the headline numbers (servers, open vulnerabilities, past SLA, due soon, severity, OS and application
issues, MBSS failures, CS gaps, and new / fixed since the previous report), a table per application, and for
each application its top findings, failed MBSS controls and CS controls with gaps. The Excel export for those
applications is attached. Server addresses and staff names are never written in the email body.

Sending needs your organisation's SMTP relay in `.env` or in the CML Application's environment variables:
`SMTP_HOST`, `SMTP_PORT` (587), `SMTP_STARTTLS` (true), `SMTP_SSL` (false), `SMTP_USERNAME`, `SMTP_PASSWORD`
and `SMTP_FROM` (see `.env.example`). Without them the page can still download the email as an `.eml` file,
which Outlook opens as a new message ready to send. `email:` in `config.yaml` sets the subject, the allowed
recipient domains, how many applications get their own section and the attachment size limit.

## Project layout

```
app.py              Streamlit entry point (pages and sidebar)
cml_app.py          launcher for a CML Application
config.yaml         application settings
agents/             model gateway (LangChain) and the remediation, scheduler and classifier agents
prompts/            system prompts, templates, few-shot examples, changelog
tools/              report loaders, OS/application rules, environment resolver, Saudi calendar, SSH runner
memory/             knowledge base (SQLite): stored recommendations and labels
workflows/          recommendation flow, fix-schedule flow, Excel export, email report, Ansible files
guardrails/         what may be sent to the model, checks on what comes back, change-window policy
evals/              tests, classifier golden set, mock model endpoint
observability/      one log line per model call (no prompt text) and per remote run (no output)
ui/                 theme, charts, shared state, the pages
```

## Tests

```bash
.venv/Scripts/python.exe -m pytest
```

The tests cover the classifier golden set, environment rules, the Saudi calendar, the recommendation flow and
the schedule guardrail. Model calls in tests go to `evals/mock_llm.py`, a small stand-in server that returns
canned answers; run `python -m evals.mock_llm` to demo the app without a real model.

## Data handling

Report files, `.env`, the knowledge base, the cache and the environment mapping are in `.gitignore`.
Only whitelisted finding fields are sent to the model; names of people never are, and IP addresses can be
masked (`guardrails/policies.yaml` → `llm_input`).

The Excel export contains server IPs and host names, like the reports. It leaves out the staff-name columns
listed in `llm_input.never_send` and says so on its Summary sheet.
