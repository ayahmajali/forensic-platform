# Local Setup Guide — MacBook + Windows

This guide takes you from a freshly-cloned repo to a running backend, a
working forensic pipeline, and a functional agent CLI, on **macOS**
(primary dev machine) and **Windows** (for cross-platform validation).

Follow the numbered steps in order. Anything prefixed with `$` is a
command to type in your terminal (macOS Terminal / VS Code terminal on
Mac, PowerShell on Windows).

---

## 0. Prerequisites (one-time)

### macOS (MacBook Pro)

Install Homebrew if you don't have it:

```bash
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then install the forensic tools and Python:

```bash
$ brew install python@3.11 sleuthkit exiftool mongodb-community@7.0
$ brew tap mongodb/brew
$ brew services start mongodb-community@7.0   # runs Mongo as a background service
```

Verify:

```bash
$ fls -V          # The Sleuth Kit
$ mmls -V
$ exiftool -ver
$ mongosh --eval 'db.runCommand({ connectionStatus: 1 })'
```

### Windows 10 / 11

1. Install **Python 3.11** from <https://www.python.org/downloads/windows/>
   (check **Add Python to PATH** during install).
2. Install **The Sleuth Kit** from <https://www.sleuthkit.org/sleuthkit/download.php>
   and add its `bin/` folder to your PATH.
3. Install **ExifTool** from <https://exiftool.org/> (rename
   `exiftool(-k).exe` to `exiftool.exe` and add to PATH).
4. Install **MongoDB Community Server** from
   <https://www.mongodb.com/try/download/community> — during install check
   "Install MongoDB as a Service".

Verify in PowerShell:

```powershell
> fls -V
> mmls -V
> exiftool -ver
> mongosh --eval 'db.runCommand({ connectionStatus: 1 })'
```

---

## 1. Pull a fresh copy of the project

You told me the project is already at `/Users/admin/bb/forensic-platform`.
If it isn't, or you want a clean clone:

```bash
$ cd ~/bb
$ git clone https://github.com/ayahmajali/forensic-platform.git
$ cd forensic-platform
```

Open the folder in VS Code:

```bash
$ code .
```

---

## 2. Create a Python virtual environment

**macOS:**
```bash
$ cd /Users/admin/bb/forensic-platform
$ python3.11 -m venv .venv
$ source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
> cd C:\path\to\forensic-platform
> python -m venv .venv
> .venv\Scripts\Activate.ps1
```

You should see `(.venv)` prepended to your prompt.

---

## 3. Install backend dependencies

```bash
(.venv) $ pip install --upgrade pip
(.venv) $ pip install -r backend/requirements.txt
```

This pulls FastAPI, Uvicorn, reportlab, pymongo and friends.

---

## 4. Configure the backend environment

```bash
(.venv) $ cp backend/.env.example backend/.env
```

Edit `backend/.env` and set:

```dotenv
# Required for the agent to be able to upload
AGENT_API_KEY=<paste a random secret here>

# Usually correct for a local Mongo:
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=forensic_platform

# Optional — enables the AI summary
OPENAI_API_KEY=
```

Generate a strong API key:

```bash
(.venv) $ python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy that string into `AGENT_API_KEY`.

---

## 5. Start the backend

```bash
(.venv) $ cd backend
(.venv) $ python start.py
# equivalent to: uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see something like:

```
[DB] Connected to MongoDB — database 'forensic_platform'
[startup] Rehydrated 0 cases from mongodb
INFO:     Uvicorn running on http://0.0.0.0:8000
```

If Mongo isn't running, you'll instead see `[DB] ... IN-MEMORY mode` — the
backend still works, cases just won't survive a restart.

---

## 6. Sanity-check the API

In a second terminal (outside the venv is fine):

```bash
$ curl -s http://localhost:8000/api/health | python -m json.tool
```

You should see `"status": "healthy"`, a `tools` map, and a
`"database": { "connected": true, "backend": "mongodb" }` block.

Open the UI: <http://localhost:8000>

Try an upload from the UI — any small `.jpg`, `.pdf` or `.dd` image. When
it finishes, test the new endpoints:

```bash
$ CASE_ID=<8-char id from the UI>
$ curl -s  http://localhost:8000/results/$CASE_ID  | python -m json.tool | head -40
$ curl -s  http://localhost:8000/timeline/$CASE_ID | python -m json.tool | head -40
$ curl -OL http://localhost:8000/report/$CASE_ID   # downloads PDF
```

---

## 7. Install and test the agent

Open a **third** terminal (keep the backend running).

**macOS:**
```bash
$ cd /Users/admin/bb/forensic-platform/agent
$ python3.11 -m venv .venv-agent
$ source .venv-agent/bin/activate
(.venv-agent) $ pip install -e .

(.venv-agent) $ export FORENSIC_API_URL="http://localhost:8000"
(.venv-agent) $ export FORENSIC_API_KEY="<the AGENT_API_KEY you set in step 4>"

(.venv-agent) $ forensic-agent health
(.venv-agent) $ forensic-agent upload ~/Desktop/test_image.dd --watch --download-report ./case.pdf
```

**Windows (PowerShell):**
```powershell
> cd C:\path\to\forensic-platform\agent
> python -m venv .venv-agent
> .venv-agent\Scripts\Activate.ps1
(.venv-agent) > pip install -e .

(.venv-agent) > $env:FORENSIC_API_URL = "http://localhost:8000"
(.venv-agent) > $env:FORENSIC_API_KEY = "<the AGENT_API_KEY from step 4>"

(.venv-agent) > forensic-agent health
(.venv-agent) > forensic-agent upload C:\Evidence\image.dd --watch --download-report .\case.pdf
```

---

## 8. Daily workflow (after initial setup)

```bash
$ cd /Users/admin/bb/forensic-platform
$ source .venv/bin/activate
$ cd backend && python start.py
```

New terminal for the agent:

```bash
$ cd /Users/admin/bb/forensic-platform/agent
$ source .venv-agent/bin/activate
$ forensic-agent upload ./evidence.dd --watch
```

---

## 9. What changed vs. the previous backend?

| File | Change |
|------|--------|
| `backend/modules/database.py`  | **New.** MongoDB case store with in-memory fallback. |
| `backend/modules/auth.py`      | **New.** API-key dependency for agent endpoints. |
| `backend/modules/pdf_report.py`| **New.** Professional reportlab-based PDF generator. |
| `backend/main.py`              | Persistence, `/analyze`, `/results/{case_id}`, `/timeline/{case_id}`, `/report/{case_id}`, `/api/report/{case_id}/pdf`, `/api/agent/upload`, startup rehydration. |
| `backend/requirements.txt`     | Added `reportlab`. |
| `backend/.env.example`         | Added `MONGODB_URI`, `MONGODB_DB`, `AGENT_API_KEY`. |
| `agent/`                       | **New.** Cross-platform CLI agent. |
| `SETUP_LOCAL.md`               | **New.** This document. |

---

## 10. Common troubleshooting

**`ModuleNotFoundError: No module named 'reportlab'`**
→ You forgot step 3, or you're in the wrong venv. Re-run
`pip install -r backend/requirements.txt`.

**`[DB] Could not reach MongoDB ... falling back to IN-MEMORY`**
→ Mongo isn't running. macOS: `brew services start mongodb-community@7.0`.
Windows: start the *MongoDB* service from the Services panel.

**Agent uploads return 503 "Agent endpoint disabled"**
→ You didn't set `AGENT_API_KEY` in `backend/.env`, or you started the
backend *before* editing the env. Stop uvicorn and restart.

**Agent uploads return 403 "Invalid API key"**
→ `FORENSIC_API_KEY` in the agent's shell doesn't match `AGENT_API_KEY`
in `backend/.env`. They must be byte-identical.

**`fls: command not found` during analysis**
→ The Sleuth Kit isn't in your PATH. On macOS re-run `brew install
sleuthkit` and confirm `which fls`. On Windows add the TSK `bin/` folder
to PATH and reopen PowerShell.
