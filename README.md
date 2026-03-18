# Digital Forensics Investigation Platform

A professional **Digital Forensics Investigation Platform** inspired by Autopsy, built with **FastAPI** and modern web technologies. Analyzes disk images, logical files, and forensic containers with a full Sleuth Kit pipeline.

---

## 🔍 Features

### Evidence Types Supported
- **E01** (EnCase forensic images)
- **DD / RAW** disk images
- **ISO** images  
- **Logical files** (any format)

### Forensic Analysis Pipeline
1. **Evidence Type Detection** — Automatic detection via magic bytes & extension
2. **Disk Image Analysis** — `mmls`, `fsstat`, `fls`, `ils` via Sleuth Kit
3. **File Recovery** — `tsk_recover` for all & deleted files
4. **Multimedia Extraction** — JPG, PNG, GIF, MP4, AVI, MOV detection & preview
5. **EXIF Metadata** — Camera model, serial number, GPS, timestamps via `exiftool`
6. **Browser Artifacts** — Chrome History, Firefox `places.sqlite`
7. **Forensic Timeline** — `fls -r -m` + `mactime` activity timeline
8. **Deleted Files Detection** — `fls -rd` highlighting
9. **Media Carving** — `photorec` / `foremost` integration
10. **Evidence Hashing** — MD5, SHA-1, SHA-256

### Search & Intelligence
- **Keyword Search Engine** — Files, content, URLs, emails, executables
- **AI Summarization** — OpenAI GPT-powered evidence summary
- **Interactive HTML Report** — Full forensic report with live search

---

## 🏗️ Architecture

```
webapp/
├── backend/
│   ├── main.py                    # FastAPI application
│   ├── start.py                   # Startup script
│   ├── requirements.txt
│   ├── .env.example
│   ├── modules/
│   │   ├── analyzer.py            # Evidence type detection & hashing
│   │   ├── disk_analysis.py       # Sleuth Kit disk analysis
│   │   ├── artifact_extractor.py  # Browser history, EXIF, multimedia
│   │   ├── timeline_builder.py    # Forensic timeline (fls + mactime)
│   │   ├── keyword_search.py      # Multi-source keyword search
│   │   ├── report_generator.py    # Interactive HTML report generator
│   │   └── ai_summary.py          # OpenAI AI summarization
│   ├── templates/
│   │   └── index.html             # Main web interface
│   ├── static/                    # CSS/JS assets
│   ├── uploads/                   # Evidence uploads (gitignored)
│   ├── reports/                   # Generated reports (gitignored)
│   └── recovered/                 # Recovered files (gitignored)
└── ecosystem.config.cjs           # PM2 configuration
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

# Optional: photorec / foremost
```

**Linux/Ubuntu:**
```bash
sudo apt-get install sleuthkit exiftool libimage-exiftool-perl
sudo apt-get install foremost  # optional carving
```

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/forensic-platform.git
cd forensic-platform/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add OPENAI_API_KEY (optional)
```

### Running

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
| `POST` | `/api/search/{job_id}` | Dynamic keyword search |
| `DELETE` | `/api/jobs/{job_id}` | Delete job & files |
| `GET` | `/api/health` | System health & tool availability |
| `POST` | `/api/config/openai` | Set OpenAI API key |

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

## 🔐 Security Notes

- Evidence files are stored locally in `uploads/`
- OpenAI API key is only held in memory (never persisted)
- Report files are accessible under `/reports/`
- For production: add authentication middleware

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | FastAPI + Python 3.10+ |
| **Frontend** | Vanilla JS + TailwindCSS (CDN) |
| **Disk Analysis** | The Sleuth Kit (TSK) |
| **Metadata** | ExifTool |
| **AI Summary** | OpenAI GPT-4o-mini |
| **Process Manager** | PM2 |
| **File Carving** | PhotoRec / Foremost |

---

## 📸 Screenshots

The platform provides:
- Modern light-themed UI with card-based layout
- Left sidebar evidence explorer tree
- Right panel with file preview & findings
- Real-time analysis progress with live log
- Interactive HTML report with embedded images

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -m 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for digital forensics investigators*
