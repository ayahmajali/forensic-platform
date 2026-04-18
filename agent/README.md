# Forensic Platform Agent

A cross-platform (macOS + Windows + Linux) command-line agent for the
Digital Forensics Investigation Platform. Runs on an investigator's machine,
uploads disk images or directories to the backend, and retrieves the PDF
report when analysis finishes.

## Install

```bash
# from the repo root
cd agent
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -e .
forensic-agent --help
```

## Configure

Set two environment variables (or pass `--api-url` / `--api-key` on each
command):

| Variable            | Purpose                                          |
|---------------------|--------------------------------------------------|
| `FORENSIC_API_URL`  | Backend base URL (default `http://localhost:8000`) |
| `FORENSIC_API_KEY`  | Must match `AGENT_API_KEY` on the server         |

**macOS / Linux:**
```bash
export FORENSIC_API_URL="http://localhost:8000"
export FORENSIC_API_KEY="your-secret-key"
```

**Windows (PowerShell):**
```powershell
$env:FORENSIC_API_URL = "http://localhost:8000"
$env:FORENSIC_API_KEY = "your-secret-key"
```

## Usage

### Upload a disk image and wait for the report
```bash
forensic-agent upload ./evidence.dd --watch --download-report ./case_report.pdf
```

### Upload a directory (auto-compressed into a zip)
```bash
forensic-agent upload /Users/investigator/collected_files --watch
```

### Poll a case's status
```bash
forensic-agent status abcd1234
```

### Download the PDF report for a completed case
```bash
forensic-agent report abcd1234 -o ./report.pdf
```

### Health-check the backend
```bash
forensic-agent health
```

## Security

* Every agent request carries an `X-API-Key` header. The backend rejects
  requests without a matching key (503 if the server has no key configured,
  401 if the header is missing, 403 on mismatch).
* Evidence is hashed locally (MD5 + SHA-256) before upload so the
  investigator can verify chain of custody.
* Files are streamed, not read into memory all at once, so multi-GB disk
  images work on modest laptops.

## Why pure Python?

`click`, `requests`, `tqdm` all publish wheels for macOS, Windows and Linux
on every supported architecture. That means the same `pip install -e .`
works everywhere with no C toolchain, making the agent defense-demo friendly
on whatever machine is available.
