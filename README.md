# Security Posture Dashboard

One place to track three security checks for the platform's servers, with AI help to fix them:

- **Vulnerabilities** — open Qualys findings, SLA status, split into OS issues and application issues
- **MBSS** — failed Minimum Baseline Security Standard controls
- **CS Controls** — coverage of antivirus, EDR, SIEM, vulnerability scanning, the Qualys agent and PAM
- **Trends** — what changed since last week (new, fixed, still open, not rescanned) and the weekly trend
- **Fix Schedule** — a per-application plan: development first, production only outside Saudi working hours
- **AI recommendations** — step-by-step fixes from a self-hosted model, stored and reused
- **Excel export** — *Export to Excel* on the Overview page: one workbook for the sidebar scope with a summary and
  charts, one row per application, and every open finding, failed MBSS check and server with a CS gap

## Run it locally

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m streamlit run app.py
```

Python 3.11 or newer is required (pandas 3). On Linux or macOS use `.venv/bin/python`.

Put the three Excel reports in `latest_Data/` (or upload them on the Settings page). The newest file of each
kind is used. The first read of a new file takes about half a minute; after that it is cached in `.cache/`.

Keep last week's files next to this week's: the **Trends** page compares two weeks and plots every week present.
A file's week comes from its data (latest *Last Scan Date Time* or *Evaluation Date*), not from when it was
copied; the CS report has no date column, so it uses the date the workbook was saved. Because the reports only
list open findings, a finding that disappears counts as *Fixed* only if its server is still in this week's
reports; otherwise it is *Not rescanned*. The rules live in `tools/history.py`.

## Connect the model

Only the endpoint is needed. Any OpenAI-compatible server works (vLLM, Ollama, TGI, LiteLLM).

- On the **Settings** page: enter the endpoint, press *Test connection*, then *Save*; or
- in `.env` (copy `.env.example`): `LLM_BASE_URL=http://llm-host:8000/v1`; or
- as an environment variable `LLM_BASE_URL` (used when `.env` has no value).

The model name is read from the endpoint. When it serves several, `gpt-oss-120b` is preferred, then Qwen
(`config.yaml` → `llm.preferred_models`). Set `LLM_MODEL` to force one.

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
- **Uploads.** If uploading a report on the Settings page fails with a 403 behind the CML proxy, add the
  environment variables `STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false` and `STREAMLIT_SERVER_ENABLE_CORS=false`
  to the application, or copy the files into `latest_Data/` instead.
- **Shared state.** The knowledge base (`memory/store/knowledge_base.sqlite`), the environment mapping and the
  cache live in the project folder, so all users of the application share them. SQLite is fine for a small
  team; it is not built for heavy concurrent writes.

`cml_app.py` listens on `127.0.0.1:$CDSW_APP_PORT`, which is what CML expects.

## Things to configure

| What | Where |
|---|---|
| Data folder, team name, SLA days, model options | `config.yaml` |
| Working days and hours, production windows, holiday freeze, soak time, canary size | `guardrails/policies.yaml` |
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
The Overview page lists inventory servers that appear in none of the reports. Only IP, host name, platform,
role, cluster, project, environment and status are read from the workbook; licence keys and credentials in it
are ignored. The workbook itself is not committed (`*.xlsx` is in `.gitignore`).

## How the fix schedule stays safe

The model never writes dates. It picks change windows by id from a list the Saudi calendar produces, and
`guardrails/output_checks.enforce_schedule` re-checks every wave: a production wave that is not in a valid
window is moved, unknown servers are dropped, forgotten servers are added. The guardrail also works out each
wave's workload itself (minutes per server, servers in parallel) and moves servers that do not fit into later
windows, so no wave holds more work than its window. A weekend day that falls inside a holiday break (for
example the Saturday between Eid and its observed day off) is frozen like the holiday itself. Eid dates in the
holiday calendar are astronomical estimates; correct them with `extra_dates` / `remove_dates` in
`guardrails/policies.yaml`.

## Project layout

```
app.py              Streamlit entry point (pages and sidebar)
cml_app.py          launcher for a CML Application
config.yaml         application settings
agents/             model gateway (LangChain) and the remediation, scheduler and classifier agents
prompts/            system prompts, templates, few-shot examples, changelog
tools/              report loaders, OS/application rules, environment resolver, Saudi calendar
memory/             knowledge base (SQLite): stored recommendations and labels
workflows/          recommendation flow, fix-schedule flow and the Excel export
guardrails/         what may be sent to the model, checks on what comes back, change-window policy
evals/              tests, classifier golden set, mock model endpoint
observability/      one log line per model call (no prompt text)
ui/                 theme, charts, shared state, the six pages
legacy/             the original scripts, kept for reference
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
