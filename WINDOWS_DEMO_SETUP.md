# Windows Demo Setup — end-to-end guide

This is the exact sequence to get the presentation working on your Parallels
Windows VM, where professors will: visit the site → click **Download for
Windows** → run the `.exe` → scan a folder → open the report in the browser.

You run **all of the "Build" steps once** (inside the VM), then on demo day
everything happens from the public URL.

---

## Architecture on demo day

```
 ┌─────────────────┐   HTTPS    ┌──────────────────────────────┐
 │ Windows VM      │─────────▶  │ Render                        │
 │ (Parallels)     │   scan     │ forensic-site.onrender.com    │
 │                 │◀─────────  │  • /download-agent             │
 │ ForensicAgent.  │   report    │  • /api/agent/findings         │
 │ exe             │            │  • /case/{id}   (HTML report)  │
 └─────────────────┘            └──────────────────────────────┘
```

No local backend. No shared folders. The Windows VM behaves exactly like any
professor's laptop would: download the `.exe` from the internet, run it, done.

---

## 0. What you need on your Mac first (one-time)

1. **Make sure `AGENT_API_KEY` is set on Render**. Without it every agent
   upload returns `503`.
   - Go to <https://dashboard.render.com> → pick the `forensic-platform` service.
   - Click **Environment** on the left.
   - Add a new variable:
     - Key: `AGENT_API_KEY`
     - Value: run this in any terminal and paste the result:
       ```bash
       python3 -c "import secrets; print(secrets.token_urlsafe(32))"
       ```
   - Click **Save Changes**. Render will redeploy (~2 min).
   - **Write the key down** — you'll paste it into the agent on the Windows VM.

2. **Set `OPENAI_API_KEY` on Render** (optional but nicer — enables the AI
   summary on the report). Same place. If you skip this, the report just uses
   the template summary.

---

## 1. Prepare the Windows VM (one-time, ~15 min)

Your VM has nothing installed. Here's everything it needs:

### 1.1 Install Python 3.11

Do **NOT** use Python 3.12 — `customtkinter` has known bundling issues with
PyInstaller on 3.12 at the time of writing.

1. In the VM, open Edge and go to <https://www.python.org/downloads/windows/>.
2. Download **Python 3.11.9** (or the latest 3.11.x) — the "Windows installer
   (64-bit)" link.
3. Run the installer. On the first screen **tick "Add python.exe to PATH"**,
   then click **Install Now**.
4. Verify in PowerShell:
   ```powershell
   python --version
   # Expected: Python 3.11.9
   pip --version
   ```

### 1.2 Install Git

1. Download from <https://git-scm.com/download/win>.
2. Run installer, accept the defaults.
3. Verify:
   ```powershell
   git --version
   ```

### 1.3 Install ExifTool (optional but recommended)

ExifTool is what the scanner uses to pull GPS, camera model, timestamps out of
photos. Without it, the scanner still works but photos have less metadata.

1. Download from <https://exiftool.org>.
2. Extract the zip. Rename `exiftool(-k).exe` to `exiftool.exe`.
3. Move `exiftool.exe` to `C:\Windows\` (or anywhere on PATH).
4. Verify:
   ```powershell
   exiftool -ver
   ```

### 1.4 Clone the repo

```powershell
cd $HOME
git clone https://github.com/ayahmajali/forensic-platform.git
cd forensic-platform
```

---

## 2. Build the Windows `.exe` (one-time, ~5 min)

```powershell
cd $HOME\forensic-platform\agent
.\build_windows.bat
```

The script will:

1. Create a clean virtualenv (`.venv-build`)
2. Install `click`, `requests`, `tqdm`, `customtkinter`, `Pillow`, `pypdf`,
   `python-docx`, `rarfile`, `pyinstaller`
3. Run PyInstaller twice — once for the GUI, once for the CLI
4. Copy the outputs into `..\backend\static\downloads\`:
   - `ForensicAgent-windows.exe` — the double-clickable GUI (~30 MB)
   - `forensic-agent-windows.exe` — the CLI binary (~25 MB)

When it finishes, test it from the VM:

```powershell
.\dist\ForensicAgent.exe
```

A window titled **"Forensic Agent 1.0.0"** should open. The **Backend URL**
field should pre-fill with `https://forensic-site.onrender.com`.

### Troubleshooting

| Symptom                                       | Fix                                                         |
|-----------------------------------------------|-------------------------------------------------------------|
| `python: command not found`                   | Re-run installer and tick **Add python.exe to PATH**        |
| PyInstaller: `Failed to collect customtkinter`| You're on Python 3.12 — install 3.11.x instead              |
| "Windows protected your PC" when running .exe | That's SmartScreen. Click **More info → Run anyway**        |
| GUI opens then immediately closes             | Run `forensic-agent-windows.exe --help` to see the real error |

---

## 3. Publish the `.exe` to the live site (one-time, ~2 min)

Now commit the Windows binaries and push. Render will redeploy automatically
and start serving the `.exe` from `https://forensic-site.onrender.com/api/agent/download/windows`.

```powershell
cd $HOME\forensic-platform

# Sanity check — should show both .exe files as untracked or modified
git status backend\static\downloads\

# Stage and commit
git add backend\static\downloads\ForensicAgent-windows.exe
git add backend\static\downloads\forensic-agent-windows.exe
git add backend\static\downloads\forensic-agent-source.zip

git commit -m "Publish Windows agent binaries for presentation"
git push origin main
```

Wait 2–3 minutes, then verify:

1. Open <https://forensic-site.onrender.com/download-agent> in any browser.
2. Click **Download for Windows**.
3. The browser should download `ForensicAgent-windows.exe` (~28–35 MB).

If you get **"ForensicAgent-windows.exe not built yet"** — the commit didn't
include the `.exe`. Re-check with `git ls-files backend/static/downloads/`.

### Note on file size

PyInstaller one-file binaries are ~30 MB because they embed the Python runtime.
GitHub's file-size soft limit is 50 MB — you're fine. If you ever hit 100 MB
use `git lfs track "*.exe"`.

---

## 4. Prepare the demo folder (~10 min, night before)

Professors are going to watch you scan **something**. Make it interesting.
Create a folder on the Windows VM with a mix of evidence types so the report
looks meaty:

```powershell
mkdir C:\DemoEvidence
cd C:\DemoEvidence

# Copy in a variety of files
# - 5-10 photos (preferably with GPS/EXIF — shot on a phone)
# - 2-3 PDFs
# - 1-2 .docx files
# - 1 .zip archive containing a few files
# - 1 screenshot of a "suspicious" webpage
```

**Browser history happens automatically** — the scanner walks the system
registry regardless of which folder you point it at. So BEFORE the demo:

1. Open Chrome on the VM, browse a few sites so there's history.
2. Open Edge, browse a couple more.
3. Install Firefox portable if you want three browsers in the chip display.

The "Web Activity" section of the report will show per-browser chips like
`Chrome (127)  ·  Edge (34)  ·  Firefox (8)`.

---

## 5. The demo script (day of)

The flow you'll walk the professors through:

### Act 1 — the download (~1 min)

> "This is the portal. Any investigator can download our agent from here."

- Visit <https://forensic-site.onrender.com> in Edge.
- Click **Download Agent** in the top nav.
- Show the download page — point out macOS/Windows cards, supported file
  types, install instructions.
- Click **Download for Windows**. Show the .exe downloading.

### Act 2 — the scan (~2 min)

> "No installer, no Python, no terminal. It's a single native desktop app."

- Double-click `ForensicAgent-windows.exe` from Downloads.
- SmartScreen warning pops up. Click **More info → Run anyway** — **this is
  fine and expected, say "unsigned academic build" and move on**.
- The GUI opens. Backend URL is pre-filled.
- Paste the `AGENT_API_KEY` from step 0 into the API Key field.
- Click **Test Connection** → green checkmark.
- Click **Choose Folder…** and pick `C:\DemoEvidence`.
- Click **▶ Start Scan**. Progress bar fills up as files are hashed.

### Act 3 — the report (~3 min)

> "The agent sent a JSON findings package. The server did the heavy lifting
> — PDF rendering, AI summary, timeline normalization. Here's what the
> investigator sees."

- When scan completes, click **Submit to Backend**.
- Click **🌐 Open Case in Browser**.
- Browser opens the polished `/case/{id}` page.
- Walk through each numbered section (1. Overview, 2. Integrity, 3. Recovered
  Files, 4. Web Activity, 5. Timeline, 6. AI Summary).
- Especially call out: **per-browser chips**, **AI summary**, **timeline**,
  **integrity certificate** (show the collapsible hash block).
- Click **Download PDF Report** — open it, show the letterhead.

### Act 4 — under the hood (optional, ~2 min)

If you have time and want to show depth:

- `https://forensic-site.onrender.com/results/{case_id}` — the raw JSON.
- `https://forensic-site.onrender.com/timeline/{case_id}` — the timeline JSON.
- `https://forensic-site.onrender.com/api/health` — server status.

---

## 6. Dry-run checklist (night before)

Do **every** item on this list the night before the presentation. Do not skip
any — demo bugs always happen on the thing you didn't rehearse.

- [ ] Render dashboard: `AGENT_API_KEY` is set
- [ ] Render dashboard: latest deploy is green (no red crosses)
- [ ] `https://forensic-site.onrender.com/api/health` returns 200
- [ ] `https://forensic-site.onrender.com/download-agent` renders correctly
- [ ] **Windows:** click Download for Windows → `.exe` downloads (not a 404)
- [ ] **Windows:** double-click the downloaded .exe → GUI opens
- [ ] **Windows:** full end-to-end scan of `C:\DemoEvidence` → Case ID shown
- [ ] **Windows:** click Open Case in Browser → report renders fully
- [ ] Report shows per-browser chips (at least 2 browsers)
- [ ] Report shows a non-empty Timeline
- [ ] Report's "Download PDF" button returns a real PDF (not an error page)
- [ ] AI summary section is populated (if you set `OPENAI_API_KEY`)
- [ ] You know the `AGENT_API_KEY` by heart or have it in a sticky note
- [ ] Parallels network is set to **Shared** (or **Bridged**) — not Host-Only

### Backup plan

If Render is slow / down / sleeping (free tier sleeps after 15 min idle):

- Hit `/api/health` **30 seconds before** the demo to wake it up.
- If it still sleeps, have a **pre-recorded screen capture** of the full flow
  as a fallback. Professors will accept "we have a video in case the free-tier
  cold-start bites us" — they won't accept five minutes of staring at a
  spinner.

---

## 7. After the presentation

You can keep everything as-is for your thesis documentation. If you want to
retire the demo afterwards:

- Revoke the API key: delete `AGENT_API_KEY` from Render env vars.
- Optionally remove the `.exe` files from `backend/static/downloads/` (they
  stay in git history regardless — that's fine).

---

*Prepared for the graduation demo — good luck, Basil.*
