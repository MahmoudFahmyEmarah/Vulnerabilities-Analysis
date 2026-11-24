# Running and configuring the Security Posture Dashboard

Start from the CML zip (`dist/Security-Posture-Dashboard-CML.zip`) or a clone of the repository. The zip has the
code, `MS_All_servers.xlsx` and the AI Platforms Inventory; it has no reports and no `.env`.

## 1. On another machine (Windows or Linux)

**Needs:**

- **Python 3.11 or newer** (3.12 is what it's tested on).
- **Optional network access:**
  - to the model endpoint, for AI recommendations and AI schedules;
  - SSH port 22 to the servers, for *Run on servers*;
  - the SMTP relay, for *Email report*.

**Steps (Windows PowerShell; on Linux use `.venv/bin/python`):**

1. Unpack the zip into a folder and open a terminal there.
2. Create the environment:
   ```powershell
   python -m venv .venv
   ```
3. Install the libraries (they come from PyPI or your pip mirror):
   ```powershell
   .venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
4. Copy the three Excel reports (vulnerabilities, MBSS, CS Controls) into `latest_Data\`. Any file names work, because
   the app recognises each report by its columns. You can also upload them later on the **Settings** page.
5. Optional: copy `.env.example` to `.env` and fill it in (see section 3).
6. Start the app:
   ```powershell
   .venv\Scripts\python.exe -m streamlit run app.py
   ```
   Then open http://localhost:8501. The first read of a new report takes about 30 seconds; after that it is cached
   in `.cache\`.

**To let colleagues on the network open it,** add `--server.address 0.0.0.0` to the start command. The app has no
login of its own and shows server addresses, and *Run on servers* can reach your servers, so only do this on a
trusted network.

## 2. On CML

1. **Create the project.** Go to **Projects → New Project** and upload the zip, or point it at the Git repository.
2. **Install the libraries once.** Start a session with a **Python 3.11+** runtime, open its terminal and run
   `pip install -r requirements.txt`. Repeat this whenever `requirements.txt` changes.
3. **Add the reports** to `latest_Data/` in the project, or upload them later on the Settings page.
4. **Create the application.** Go to **Applications → New Application** and set:
   - **Script:** `cml_app.py` (it listens on `127.0.0.1:$CDSW_APP_PORT`, which is what CML expects)
   - **Runtime:** the same Python 3.11+ runtime
   - **Resource profile:** 2 vCPU and 8 GB is enough for the current report sizes
   - **Environment variables:** those in section 3, at least `LLM_BASE_URL`
5. **Start it** and open the application link.

**Check before going live:**

- **Access:** restrict the application to your team.
- **Network from the CML pod:**
  - to the model endpoint;
  - SSH port 22 to the servers, for Run on servers;
  - the SMTP relay, for Email report.

  The pages load without these connections; only those features stop working.
- **Host keys:** add your servers to `~/.ssh/known_hosts`. On CML the home folder is the project folder
  (`/home/cdsw`). You can also name a file in `remote_run.known_hosts_file`. Without either, every user has to
  accept each server's key in every session.
- **Uploads:** if uploading on the Settings page gives a 403 behind the CML proxy, add
  `STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=false` and `STREAMLIT_SERVER_ENABLE_CORS=false` to the application, or
  copy the files into `latest_Data/` instead.
- **Shared state:** everyone shares the knowledge base (`memory/store/`), the environment mapping and the cache.
  Back up `memory/store/` if the stored recommendations matter: SQLite file locking is unreliable on network
  storage.
- **Updates:** after you upload new code or change environment variables, restart the application.

## 3. What to configure

### Secrets and connections

On another machine these go in `.env`; on CML they go in the application's environment variables. A value in
`.env` wins; a blank one falls back to the environment variable.

| Variable | Needed for | Notes |
|---|---|---|
| `LLM_BASE_URL` | AI recommendations, AI schedule, AI classification | Any OpenAI-compatible endpoint, e.g. `http://llm-host:8000/v1` |
| `LLM_MODEL` | optional | Blank means the endpoint's model (gpt-oss-120b is preferred) |
| `LLM_API_KEY` | only if the endpoint needs one | |
| `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_STARTTLS` (true), `SMTP_SSL` (false), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | sending from Email report | Without them the page still offers the `.eml` download |
| `DATA_DIR` | optional | Reads reports from another folder instead of `latest_Data/` |
| `MODEL_SETTINGS_EDITABLE` | optional | On CML the Settings page can't change the model endpoint; `1` unlocks it, `0` locks it anywhere |

### `config.yaml`

Changes apply without a restart.

- `app`: title, team name, data folder, team server list (`MS_All_servers.xlsx`), the AI inventory file and its
  sheet-to-platform names.
- `sla_days` and `sla_due_soon_days`: the SLA per severity and when a finding counts as "due soon".
- `llm`: preferred models, temperature and timeout.
- `email`: subject, `allowed_recipient_domains` (worth setting to your company domain so reports can't go
  outside), how many applications get their own section, attachment on/off and its size limit.

### `guardrails/policies.yaml`

The rules. Changes also apply without a restart.

- `calendar`: working days and hours, and holidays. Eid dates are estimates, so correct them with `extra_dates` /
  `remove_dates`.
- `production`: night and weekend change windows.
- `scheduling`: soak days before production, canary share, servers in parallel, minutes per server per type of
  work, and `waves` (the default of one development and one production wave, at most 4 in total, and the
  "Automatic" threshold).
- `remote_run`:
  - `enabled`: set it to false to switch Run on servers off entirely;
  - session length (30 minutes), time-outs, servers per run;
  - `allow_other_hosts` (keep it false);
  - `known_hosts_file`.
- `llm_input`: mask IP addresses before they go to the model, and the staff-name columns that are never sent.

### In the app (Settings page)

- Upload reports and fix a report's week.
- Map servers to production or development (saved to `reference/environment_overrides.csv`); unmapped servers
  count as production.
- Label findings the OS / application rules cannot place.

## Minimum to get going

Python with the libraries installed, plus the three reports. Add `LLM_BASE_URL` for the AI features, the
`SMTP_*` settings to send email, and SSH access plus `known_hosts` for Run on servers.
