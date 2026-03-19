# Digital Forensics Investigation Platform

A professional **Digital Forensics Investigation Platform** inspired by Autopsy, built with **FastAPI** and modern web technologies. Analyzes disk images, logical files, and forensic containers with a full Sleuth Kit pipeline.

---

## 🚀 Live URLs

| Service | URL |
|---------|-----|
| **Frontend (Cloudflare Pages)** | https://forensic-platform.pages.dev |
| **Backend API (Render.com)** | https://forensic-platform.onrender.com |
| **GitHub Repository** | https://github.com/ayahmajali/forensic-platform |

> ⚠️ **Note:** The Render.com free tier sleeps after 15 minutes of inactivity. The **first request may take ~30 seconds** to wake the server. Subsequent requests are fast.

---

## 🔍 Features

### Evidence Types Supported
- **E01** (EnCase forensic images)
- **DD / RAW** disk images
- **ISO** images  
- **Logical files** (PDF, DOCX, JPG, TXT, ZIP, etc.)

### Forensic Analysis Pipeline
1. **Evidence Type Detection** — Automatic detection via magic bytes & extension
2. **Cryptographic Hashing** — MD5, SHA-1, SHA-256 chain of custody
3. **Disk Image Analysis** — `mmls`, `fsstat`, `fls`, `ils` via Sleuth Kit
4. **File Recovery** — `tsk_recover` for all & deleted files
5. **Multimedia Extraction** — JPG, PNG, GIF, MP4, AVI, MOV detection & preview
6. **EXIF Metadata** — Camera model, serial number, GPS, timestamps via `exiftool`
7. **Browser Artifacts** — Chrome History, Firefox `places.sqlite`
8. **Forensic Timeline** — `fls -r -m` + `mactime` MAC-time activity timeline
9. **Deleted Files Detection** — `fls -rd` highlighting
10. **Media Carving** — `photorec` / `foremost` integration

### Search & Intelligence
- **Keyword Search Engine** — Files, content, URLs, emails, executables, SQLite databases
- **AI Summarization** — OpenAI GPT-4o-mini powered evidence summary
- **Interactive HTML Report** — Full forensic report with live search, lightbox, and timeline

---

## 🏗️ Architecture

```
forensic-platform/
├── backend/                         # FastAPI Python server (deployed to Render.com)
│   ├── main.py                      # FastAPI application + all routes
│   ├── start.py                     # Dev startup script
│   ├── requirements.txt             # Python dependencies
│   ├── modules/
│   │   ├── analyzer.py              # Evidence type detection & hashing
│   │   ├── disk_analysis.py         # Sleuth Kit disk analysis
│   │   ├── artifact_extractor.py    # Browser history, EXIF, multimedia
│   │   ├── timeline_builder.py      # Forensic timeline (fls + mactime)
│   │   ├── keyword_search.py        # Multi-source keyword search
│   │   ├── report_generator.py      # Interactive HTML report generator
│   │   └── ai_summary.py            # OpenAI GPT-4o-mini summarization
│   └── templates/
│       └── index.html               # Main web interface
├── cloudflare-frontend/             # Cloudflare Pages static deployment
│   ├── index.html                   # Frontend UI (copied from backend/templates)
│   ├── custom.css                   # Custom styles
│   ├── _worker.js                   # CF Worker: proxies /api/* to Render backend
│   └── _routes.json                 # Cloudflare Pages routing config
├── docs/
│   └── documentation.html          # Full technical documentation (HTML)
├── DOCUMENTATION.md                 # Full technical documentation (Markdown)
├── render.yaml                      # Render.com deployment config
├── Procfile                         # Process definition
└── ecosystem.config.cjs             # PM2 config (local development)
```

---

## 🚀 Quick Start

### Prerequisites

**Windows:**
```bash
# Install The Sleuth Kit
# Download from: https://www.sleuthkit.org/sleuthkit/download.php
# Add to PATH

# Install exiftool
# Download from: https://exiftool.org/
```

**Linux/Ubuntu:**
```bash
sudo apt-get install sleuthkit exiftool libimage-exiftool-perl
sudo apt-get install foremost  # optional carving
```

### Installation

```bash
# Clone repository
git clone https://github.com/ayahmajali/forensic-platform.git
cd forensic-platform/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment (optional)
cp .env.example .env
# Edit .env and add OPENAI_API_KEY (optional)
```

### Running Locally

```bash
# Start the server
python start.py

# Or with uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open browser: **http://localhost:8000**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main web interface |
| `POST` | `/api/investigate` | Upload evidence & start analysis |
| `GET` | `/api/status/{job_id}` | Get job status & progress |
| `GET` | `/api/jobs` | List all jobs |
| `GET` | `/api/report/{job_id}` | Get full report JSON |
| `GET` | `/api/report-file/{job_id}` | View interactive HTML report |
| `POST` | `/api/search/{job_id}` | Dynamic keyword search |
| `DELETE` | `/api/jobs/{job_id}` | Delete job & files |
| `GET` | `/api/health` | System health & tool availability |
| `POST` | `/api/config/openai` | Set OpenAI API key |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | FastAPI + Python 3.11 |
| **Frontend** | Vanilla JS + Tailwind CSS (CDN) |
| **Disk Analysis** | The Sleuth Kit (TSK) |
| **Metadata** | ExifTool |
| **AI Summary** | OpenAI GPT-4o-mini |
| **Frontend Hosting** | Cloudflare Pages |
| **Backend Hosting** | Render.com |
| **Version Control** | Git + GitHub |
| **Process Manager** | PM2 (dev) / uvicorn (prod) |
| **File Carving** | PhotoRec / Foremost |

---

## ☁️ Deployment

### Cloudflare Pages (Frontend)
The `cloudflare-frontend/` folder is deployed to Cloudflare Pages. It contains a `_worker.js` that proxies all `/api/*` requests to the Render.com backend.

**Live URL:** https://forensic-platform.pages.dev

### Render.com (Backend)
The `backend/` folder is deployed to Render.com as a Python web service.

**Setup:**
1. Sign up at https://render.com
2. New Web Service → Connect `ayahmajali/forensic-platform`
3. Root Directory: `backend`
4. Build: `pip install -r requirements.txt`
5. Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add environment variables:
   - `OPENAI_API_KEY` = your key
   - `MONGODB_URI` = your MongoDB Atlas URI (optional)

---

## 📊 Interactive Report Sections

1. **AI Investigation Summary** — GPT-generated executive summary
2. **Evidence Information** — Name, type, size, hashes
3. **Statistics Dashboard** — Files, deleted, images, videos counts
4. **Disk Partitions** — mmls output table
5. **Filesystem Info** — fsstat parsed output
6. **All Files** — Searchable file listing
7. **Deleted Files** — Highlighted deleted entries
8. **Multimedia Preview** — Image lightbox & video player
9. **Documents** — PDF, Word, Excel catalog
10. **Browser History** — Chrome/Firefox URL table
11. **EXIF Metadata** — Camera data with GPS map links
12. **Forensic Timeline** — MAC-time activity table
13. **Keyword Search Results** — All search hits by keyword

---

## 📄 Documentation

Full technical documentation available at:
- **HTML (interactive):** `docs/documentation.html`
- **Markdown:** `DOCUMENTATION.md`

---

## 🔐 Security Notes

- Evidence files are stored locally in `uploads/`
- OpenAI API key is only held in memory (never persisted to disk)
- For production: add authentication middleware
- CORS currently allows all origins — restrict for production use

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for digital forensics investigators — Graduate Project 2025*
*Author: Ayah Majali | GitHub: [ayahmajali](https://github.com/ayahmajali)*
