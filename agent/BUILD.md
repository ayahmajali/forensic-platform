# Building the Agent Binaries

The agent ships as a **single-file executable** on macOS and Windows so end
users don't need Python on their investigation machine. Both binaries are
produced with [PyInstaller](https://pyinstaller.org/) from the exact same
Python source (`forensic_agent.py` + `scanner.py`).

There are no cross-compilers here — you must build each platform's binary on
that platform. GitHub Actions or a local VM are the two usual options.

---

## macOS

```bash
cd agent
chmod +x build_macos.sh
./build_macos.sh
```

You'll get:

- `agent/dist/forensic-agent-macos` — the binary you can ship
- `backend/static/downloads/forensic-agent-macos` — auto-published so
  `GET /api/agent/download/macos` serves it

### Universal binary (Intel + Apple Silicon)

Build on each architecture, then merge:

```bash
# On Apple Silicon:
./build_macos.sh
cp dist/forensic-agent-macos /tmp/forensic-agent-arm64

# On Intel (or cross-building with arch -x86_64):
./build_macos.sh
cp dist/forensic-agent-macos /tmp/forensic-agent-x86_64

# Merge:
lipo -create -output forensic-agent-macos \
    /tmp/forensic-agent-x86_64 \
    /tmp/forensic-agent-arm64
cp forensic-agent-macos ../backend/static/downloads/forensic-agent-macos
```

---

## Windows

Open **PowerShell** or **Command Prompt** inside `agent\`:

```powershell
cd agent
.\build_windows.bat
```

Outputs:

- `agent\dist\forensic-agent-windows.exe`
- `backend\static\downloads\forensic-agent-windows.exe`

---

## Source archive (optional)

Both build scripts also pack the agent source into
`backend/static/downloads/forensic-agent-source.zip` so the "From source" tab
on `/download-agent` can serve it.

---

## What ends up inside the binary

| Bundled                | Not bundled (system-installed)        |
|-----------------------:|:--------------------------------------|
| Python 3.11 runtime    | `exiftool` (optional, for EXIF)       |
| `click` CLI framework  | `unrar` / `unar` (optional, for RAR)  |
| `requests` HTTP client | `uvicorn` / backend — hosted remotely |
| `tqdm` progress bars   |                                       |
| `pypdf` (optional)     |                                       |
| `python-docx` (opt.)   |                                       |
| `rarfile` (opt.)       |                                       |

The binary is self-contained for its **core** job: walking a folder, hashing,
metadata extraction, submission to the backend. The "optional" tools enable
richer parsing — if they're missing at scan time, the scanner simply records a
note in `errors[]` and keeps going.

---

## Troubleshooting

**PyInstaller crashes with `Unable to find "Python.framework"`**
Re-install Python 3.11 from python.org — the Homebrew build sometimes ships
without the shared framework PyInstaller needs.

**macOS: "forensic-agent-macos" can't be opened — developer unverified**
That's macOS Gatekeeper. On a trusted machine:
```bash
xattr -dr com.apple.quarantine ./forensic-agent-macos
```
or right-click → **Open** the first time.

**Windows: SmartScreen warns the download is unrecognised**
The `.exe` is unsigned. Click *More info → Run anyway*, or pass the binary
through your code-signing pipeline before distributing.

**Binary is huge (~40 MB+)**
Expected — PyInstaller bundles the Python runtime. Use `--onedir` instead of
`--onefile` during development to avoid repacking on each change.
