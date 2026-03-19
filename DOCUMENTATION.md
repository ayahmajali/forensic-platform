# Digital Forensics Investigation Platform
## Full Technical Documentation
### Graduate Research Project — Computer Science / Cybersecurity

---

> **Project Repository:** https://github.com/ayahmajali/forensic-platform  
> **Live Demo:** https://forensic-platform.onrender.com  
> **Version:** 1.0.0  
> **Author:** Ayah Majali  
> **Date:** March 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Core Modules — Detailed Description](#4-core-modules)
5. [Forensic Analysis Pipeline](#5-forensic-analysis-pipeline)
6. [API Reference](#6-api-reference)
7. [Frontend Design & UI/UX](#7-frontend-design--uiux)
8. [Database & Storage Architecture](#8-database--storage-architecture)
9. [Security & Chain of Custody](#9-security--chain-of-custody)
10. [Deployment Architecture](#10-deployment-architecture)
11. [Testing Strategy](#11-testing-strategy)
12. [Project Structure](#12-project-structure)
13. [Limitations & Future Work](#13-limitations--future-work)
14. [References](#14-references)

---

## 1. Project Overview

### 1.1 Introduction

The **Digital Forensics Investigation Platform** is a web-based forensic analysis system designed to assist digital investigators, law enforcement professionals, and cybersecurity researchers in processing, analyzing, and reporting on digital evidence. The platform automates the traditionally manual and time-intensive process of forensic analysis by integrating industry-standard tools into a single, accessible web interface.

Digital forensics is a branch of forensic science encompassing the recovery, investigation, and analysis of material found in digital devices — often in relation to computer crime. Traditional digital forensic workflows require investigators to use multiple specialized command-line tools, manually correlate findings, and produce written reports. This platform unifies the entire workflow into an automated, AI-assisted pipeline.

### 1.2 Problem Statement

Digital forensic investigators face several challenges:

- **Tooling fragmentation**: Different tools for disk analysis, file recovery, browser artifacts, metadata extraction, and reporting
- **Manual correlation**: Findings from multiple tools must be correlated manually, which is error-prone and time-consuming
- **Accessibility**: Powerful forensic tools (Sleuth Kit, ExifTool) require significant technical expertise to operate via command line
- **Report generation**: Producing professional, court-admissible reports is a laborious manual process
- **Scale**: Modern investigations involve terabytes of data; manual analysis is not scalable

### 1.3 Objectives

1. Build a unified web platform that integrates all major forensic analysis tools
2. Implement an automated multi-step analysis pipeline
3. Support multiple evidence types: E01, DD/RAW, ISO disk images, and logical files
4. Generate interactive, professional HTML reports suitable for legal proceedings
5. Integrate AI-powered summarization to highlight key findings
6. Provide a keyword search engine across all extracted evidence
7. Deliver a mobile-responsive, accessible web interface

### 1.4 Scope

The platform covers the following forensic domains:

| Domain | Coverage |
|---|---|
| Disk Analysis | Partition tables, filesystem metadata, inode analysis |
| File Recovery | Allocated and deleted file recovery |
| Browser Forensics | Chrome History, Firefox places.sqlite |
| Multimedia Evidence | Images, videos with preview support |
| Metadata Analysis | EXIF data, GPS coordinates, camera information |
| Timeline Reconstruction | MAC-time (Modified, Accessed, Changed) timelines |
| Keyword Intelligence | Deep search across filenames, content, URLs, metadata |
| Cryptographic Verification | MD5, SHA-1, SHA-256 evidence hashing |
| AI Summarization | GPT-powered natural language findings summary |
| Report Generation | Interactive HTML forensic reports |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT (Browser)                         │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐  │
│  │  Upload UI    │   │  Progress     │   │  HTML Report  │  │
│  │  (HTML/CSS/JS)│   │  Dashboard    │   │  Viewer       │  │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘  │
└──────────┼───────────────────┼───────────────────┼──────────┘
           │ HTTP/REST          │ Polling            │ HTTP
           ▼                   ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                  FastAPI Backend (Python 3.11)               │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              main.py — API Gateway                   │   │
│  │  POST /api/investigate  GET /api/status/{id}         │   │
│  │  GET  /api/jobs         GET /api/report-file/{id}    │   │
│  │  POST /api/search/{id}  GET /api/health              │   │
│  └────────────────────┬─────────────────────────────────┘   │
│                       │ Background Task                      │
│                       ▼                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Forensic Analysis Pipeline                 │   │
│  │                                                      │   │
│  │  analyzer.py ──► disk_analysis.py ──► artifact_     │   │
│  │                                       extractor.py  │   │
│  │  timeline_builder.py ──► keyword_search.py ──►      │   │
│  │  ai_summary.py ──► report_generator.py              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  Sleuth Kit  │  │  ExifTool    │  │  OpenAI API     │   │
│  │  (TSK)       │  │  (External)  │  │  (GPT-4o-mini)  │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────┐              ┌─────────────────────┐
│  Local File System  │              │   MongoDB Atlas      │
│  /tmp/forensic/     │              │  (Investigation DB)  │
│  uploads/           │              │  investigations      │
│  reports/           │              │  reports             │
│  recovered/         │              │  artifacts           │
└─────────────────────┘              └─────────────────────┘
```

### 2.2 Request-Response Flow

```
User uploads evidence file
         │
         ▼
POST /api/investigate
  ├── Save file to /uploads/{job_id}_{filename}
  ├── Create job record in memory store
  ├── Launch background async task
  └── Return { job_id, status: "queued" }
         │
         ▼ (Background)
run_full_analysis()
  ├── Step 1:  detect_evidence_type()      [analyzer.py]
  ├── Step 2:  compute_hashes()            [analyzer.py]
  ├── Step 3:  run_full_disk_analysis()    [disk_analysis.py]
  ├── Step 3b: recover_files()             [disk_analysis.py]
  ├── Step 4:  extract_all()               [artifact_extractor.py]
  ├── Step 5:  build_timeline()            [timeline_builder.py]
  ├── Step 6:  search_all(keywords)        [keyword_search.py]
  ├── Step 7:  generate_summary()          [ai_summary.py]
  └── Step 8:  generate()                  [report_generator.py]
         │
         ▼
Client polls GET /api/status/{job_id}
  └── Returns progress %, logs, status
         │
         ▼ (status == "completed")
Client opens GET /api/report-file/{job_id}
  └── Returns full interactive HTML report
```

### 2.3 Concurrency Model

The platform uses Python's `asyncio`-based concurrency model via FastAPI:

- **API endpoints** are `async` coroutines handled by `uvicorn`'s event loop
- **Analysis pipeline** runs as a `BackgroundTask` — non-blocking for the HTTP server
- **File I/O** uses `aiofiles` for asynchronous reads/writes
- **External tools** (TSK, ExifTool) are invoked via `subprocess.run()` with timeouts

This allows the server to handle multiple concurrent upload/status requests while analysis pipelines run independently for each job.

---

## 3. Technology Stack

### 3.1 Backend — Python 3.11

**Why Python 3.11?**

Python was selected as the backend language for the following reasons:

| Reason | Detail |
|---|---|
| **Forensic ecosystem** | The Sleuth Kit, ExifTool, and most forensic libraries have mature Python bindings and wrappers |
| **subprocess integration** | Python's `subprocess` module provides clean integration with command-line forensic tools (mmls, fls, tsk_recover) |
| **hashlib** | Built-in MD5, SHA-1, SHA-256 cryptographic hashing without external dependencies |
| **sqlite3** | Built-in SQLite support essential for parsing Chrome History and Firefox places.sqlite browser databases |
| **struct/bytes** | Low-level binary file parsing for magic byte detection and disk image header analysis |
| **asyncio** | Native async/await support for non-blocking I/O across the analysis pipeline |
| **Version 3.11** | 10–60% faster than Python 3.9; improved error messages; better traceback formatting |

**Python Standard Library Modules Used:**

```
hashlib    — MD5, SHA-1, SHA-256 evidence hashing
sqlite3    — Browser history database parsing
subprocess — Invoking Sleuth Kit and ExifTool CLI tools
pathlib    — Cross-platform file path handling
struct     — Binary file header parsing (magic bytes)
re         — Regular expression keyword matching
os         — Environment variables, file system operations
asyncio    — Asynchronous task coordination
json       — Data serialization for API responses
shutil     — File copy, tree deletion, tool discovery (shutil.which)
base64     — Image embedding in HTML reports
datetime   — Timestamp generation and formatting
```

---

### 3.2 FastAPI

**Version:** `>=0.109.0`  
**Role:** Web framework and REST API layer

**Why FastAPI over Flask or Django?**

FastAPI was chosen as the web framework for the following technical reasons:

| Feature | FastAPI | Flask | Django |
|---|---|---|---|
| **Async support** | Native (asyncio) | Limited (requires extensions) | Limited (ASGI via Channels) |
| **Performance** | ~3× faster than Flask | Baseline | Slower (ORM overhead) |
| **Automatic docs** | Built-in Swagger UI + ReDoc | Manual | Manual |
| **Type validation** | Pydantic integration | Manual | Manual |
| **Background tasks** | Built-in `BackgroundTasks` | Requires Celery/RQ | Requires Celery |
| **File uploads** | Built-in `UploadFile` | Manual `request.files` | Manual |
| **Modern Python** | Designed for Python 3.6+ type hints | Legacy patterns | Legacy patterns |

**Key FastAPI Features Used in This Project:**

```python
# 1. UploadFile — handles multipart form data for evidence uploads
@app.post("/api/investigate")
async def start_investigation(evidence: UploadFile = File(...)):
    ...

# 2. BackgroundTasks — runs analysis without blocking the HTTP response
async def start_investigation(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_full_analysis, job_id, ...)

# 3. HTMLResponse — serves generated forensic reports
@app.get("/api/report-file/{job_id}", response_class=HTMLResponse)
async def serve_report_file(job_id: str):
    ...

# 4. StaticFiles — serves CSS, JS, and recovered media files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)))

# 5. Jinja2Templates — renders the main HTML UI page
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# 6. CORSMiddleware — enables cross-origin requests for frontend/API separation
app.add_middleware(CORSMiddleware, allow_origins=["*"])
```

---

### 3.3 The Sleuth Kit (TSK)

**Version:** 4.x  
**Role:** Core disk image analysis and file system forensics

The Sleuth Kit is the industry-standard open-source digital forensics toolkit developed by Brian Carrier. It is the same toolkit underlying Autopsy (the leading desktop forensic platform). TSK provides a suite of command-line tools that work directly with raw disk images without modifying them — essential for forensically sound investigation.

**Tools Integrated:**

| Tool | Purpose | Usage in Platform |
|---|---|---|
| `mmls` | Partition table analysis | Lists all partitions, their start/end sectors, sizes, and types (MBR, GPT, BSD) |
| `fsstat` | Filesystem statistics | Extracts filesystem type (NTFS, FAT32, ext4), volume name, block size, inode count |
| `fls` | File listing | Lists allocated and deleted files with inodes; `-r` for recursive, `-d` for deleted only |
| `ils` | Inode listing | Lists inode metadata for all files including deleted ones |
| `tsk_recover` | File recovery | Recovers all files (allocated + deleted) from a partition to an output directory |
| `mactime` | Timeline generation | Converts `fls` body file output into sorted MAC-time activity timeline |

**Why TSK Over Commercial Tools?**

1. **Open source** — No licensing costs; appropriate for academic/research use
2. **Court-accepted** — TSK output is accepted in legal proceedings worldwide
3. **Read-only operation** — TSK never modifies the evidence image
4. **Scripting support** — Command-line interface integrates cleanly with Python `subprocess`
5. **Format support** — Handles E01 (EnCase), DD/RAW, AFF, VMDK, VHD, ISO

**Example TSK Command Execution in Platform:**

```python
# From disk_analysis.py
def run_mmls(self) -> Dict:
    stdout, stderr, rc = self._run_cmd(["mmls", str(self.image_path)])
    # Parses partition table: slot, start, end, length, description

def run_fls(self, offset: int = 0) -> List[Dict]:
    cmd = ["fls", "-r", "-m", "/", "-o", str(offset), str(self.image_path)]
    # Lists all files recursively with MAC times

def run_deleted_files(self, offset: int = 0) -> List[Dict]:
    cmd = ["fls", "-r", "-d", "-o", str(offset), str(self.image_path)]
    # Lists only deleted files — highlighted in red in the report
```

---

### 3.4 ExifTool

**Version:** 12.x  
**Role:** Metadata extraction from images, videos, and documents

ExifTool by Phil Harvey is the world's most widely used metadata extraction tool, supporting over 100 file formats. It extracts EXIF (Exchangeable Image File Format) data embedded in digital files by cameras, smartphones, and applications.

**Why ExifTool?**

| Reason | Detail |
|---|---|
| **Breadth** | Reads metadata from 100+ formats: JPEG, PNG, TIFF, PDF, MP4, MOV, DOCX, etc. |
| **Forensic detail** | Extracts GPS coordinates, camera serial numbers, software signatures, and timestamps that users cannot easily edit |
| **JSON output** | `exiftool -json` returns structured JSON directly consumable by Python |
| **Chain of evidence** | Metadata timestamps can contradict or corroborate claimed timelines |
| **GPS mapping** | Extracted coordinates link directly to Google Maps for location intelligence |

**Metadata Extracted in Platform:**

```
Make            — Camera/device manufacturer (e.g., Apple, Canon, Samsung)
Model           — Device model (e.g., iPhone 15 Pro, Canon EOS R5)
SerialNumber    — Unique device serial number (device attribution)
DateTimeOriginal — When the photo was originally taken
CreateDate      — File creation timestamp
ModifyDate      — Last modification timestamp
GPSLatitude     — Geographic latitude (decimal degrees)
GPSLongitude    — Geographic longitude (decimal degrees)
GPSAltitude     — Elevation above sea level
Software        — Application that created/edited the file
ImageWidth/Height — Image dimensions
ExposureTime    — Camera exposure settings
FNumber         — Aperture settings
```

**Integration in Platform:**

```python
# From artifact_extractor.py
def extract_exif_metadata(self, file_path: Path) -> Dict:
    cmd = ["exiftool", "-json", "-GPS*", "-Make", "-Model",
           "-SerialNumber", "-DateTime*", "-Software", str(file_path)]
    stdout, _, rc = self._run_cmd(cmd)
    if rc == 0 and stdout:
        data = json.loads(stdout)[0]
        return {
            "make": data.get("Make", ""),
            "model": data.get("Model", ""),
            "serial_number": data.get("SerialNumber", ""),
            "gps_latitude": data.get("GPSLatitude", ""),
            "gps_longitude": data.get("GPSLongitude", ""),
            ...
        }
```

---

### 3.5 SQLite3 (Browser Artifact Parsing)

**Role:** Parsing browser history databases

Modern web browsers store their history, bookmarks, cookies, and cached data in SQLite database files. The platform uses Python's built-in `sqlite3` module to query these databases directly.

**Browser Databases Parsed:**

| Browser | Database File | Table | Key Fields |
|---|---|---|---|
| **Google Chrome** | `History` | `urls`, `visits` | `url`, `title`, `last_visit_time`, `visit_count` |
| **Mozilla Firefox** | `places.sqlite` | `moz_places`, `moz_historyvisits` | `url`, `title`, `last_visit_date`, `visit_count` |
| **Microsoft Edge** | `History` | `urls`, `visits` | Same as Chrome (Chromium-based) |

**Why Direct SQLite Parsing?**

1. **No browser required** — Databases can be parsed even when the browser is not installed
2. **Deleted entries** — SQLite's WAL (Write-Ahead Log) and freelist may contain deleted history rows recoverable with specialized queries
3. **Portable** — Browser profile databases can be extracted from disk images and analyzed offline
4. **Timestamps** — Chrome stores timestamps as microseconds since Jan 1, 1601 (WebKit epoch); Firefox uses microseconds since Unix epoch — both converted to human-readable format

**Query Examples:**

```python
# Chrome History query (from artifact_extractor.py)
query = """
    SELECT urls.url, urls.title, urls.last_visit_time, urls.visit_count
    FROM urls
    LEFT JOIN visits ON urls.id = visits.url
    ORDER BY urls.last_visit_time DESC
    LIMIT 1000
"""

# Firefox places.sqlite query
query = """
    SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date
    FROM moz_places
    JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
    ORDER BY moz_historyvisits.visit_date DESC
    LIMIT 1000
"""
```

---

### 3.6 OpenAI GPT API (AI Summarization)

**Model:** `gpt-4o-mini`  
**Role:** Natural language generation for forensic investigation summaries

The platform integrates OpenAI's GPT language model to automatically generate concise, professional forensic summaries from raw analysis data. This transforms structured JSON results into readable investigator narratives.

**Why AI Summarization in Forensics?**

| Benefit | Detail |
|---|---|
| **Accessibility** | Non-technical stakeholders (lawyers, managers, courts) can understand findings without forensic expertise |
| **Speed** | Produces a professional summary in seconds that would take hours to write manually |
| **Consistency** | Standardized report format regardless of investigator |
| **Pattern recognition** | GPT can identify correlations across large datasets (e.g., connecting browser history to deleted files) |
| **Actionable insights** | Highlights the most suspicious findings and recommends investigative next steps |

**Prompt Engineering Approach:**

The platform sends structured forensic data to GPT with a carefully crafted system prompt:

```
System: You are a senior digital forensics expert writing a professional 
investigation summary. Be concise, factual, and highlight the most 
significant findings. Use forensic terminology correctly. Structure your 
response with clear sections.

User: Analyze this forensic evidence:
- Evidence: {filename} ({type})
- SHA-256: {hash}
- Files recovered: {count}
- Deleted files: {deleted_count}
- Browser history entries: {browser_count}
- Top visited URLs: {top_urls}
- Suspicious keywords found: {keywords_with_hits}
- EXIF metadata: {metadata_summary}
- Timeline events: {timeline_count}
```

**Graceful Fallback:**

If OpenAI API key is not configured or API call fails, the platform automatically generates a structured template-based summary using `generate_local_summary()` — ensuring the system is fully functional without AI credentials.

---

### 3.7 Python `hashlib` (Evidence Integrity)

**Role:** Cryptographic hash computation for evidence integrity and chain of custody

Hash functions are foundational to digital forensics — they prove that evidence has not been modified since collection. Courts require evidence integrity verification.

**Hash Algorithms Implemented:**

| Algorithm | Output | Use Case |
|---|---|---|
| **MD5** | 128-bit (32 hex chars) | Legacy compatibility; quick verification |
| **SHA-1** | 160-bit (40 hex chars) | Broader compatibility |
| **SHA-256** | 256-bit (64 hex chars) | **Primary** — current standard for forensic verification |

**Implementation (Chunked for Large Files):**

```python
# From analyzer.py — handles files of any size
def compute_hashes(self) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()

    with open(self.evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):  # 64KB chunks
            md5.update(chunk)
            sha256.update(chunk)
            sha1.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
    }
```

Chunked reading ensures that even terabyte-sized disk images can be hashed without exceeding available RAM.

---

### 3.8 Jinja2 (HTML Report Templating)

**Version:** `>=3.1.0`  
**Role:** Server-side HTML rendering for the main web interface

Jinja2 is a modern, designer-friendly Python templating engine used by Flask, Django, and many other frameworks.

**Why Jinja2?**

1. **FastAPI integration** — FastAPI's `Jinja2Templates` class provides direct integration
2. **Security** — Auto-escaping prevents XSS attacks when rendering user-supplied filenames in reports
3. **Server-side rendering** — The main `index.html` page is rendered server-side, ensuring proper content delivery

**Usage in Platform:**

```python
# Rendering the main page
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
```

The forensic **HTML reports** (generated by `report_generator.py`) use Python string formatting rather than Jinja2, allowing the report to be a fully self-contained single HTML file with no external template dependencies.

---

### 3.9 aiofiles (Asynchronous File I/O)

**Version:** `>=23.2.0`  
**Role:** Non-blocking file operations for evidence uploads

`aiofiles` wraps Python's standard file I/O operations with async/await support, preventing the HTTP server from blocking while large evidence files are being saved to disk.

```python
# From main.py — non-blocking evidence upload
async with aiofiles.open(str(evidence_path), 'wb') as f:
    content = await evidence.read()
    await f.write(content)
```

Without `aiofiles`, a 10GB disk image upload would block the entire server for minutes.

---

### 3.10 MongoDB (Investigation Database)

**Client:** `pymongo>=4.6.0`  
**Service:** MongoDB Atlas (cloud-hosted)  
**Role:** Persistent storage for investigation jobs, reports, and artifacts

While the current implementation uses an in-memory Python dictionary (`investigation_jobs: dict`) for job tracking, MongoDB is configured for production use. The schema design supports full investigation lifecycle management.

**Why MongoDB Over SQL?**

| Reason | Detail |
|---|---|
| **Schema flexibility** | Forensic findings vary widely (a disk image analysis has very different fields from a logical file) — MongoDB's document model accommodates this naturally |
| **Nested documents** | Browser history, file lists, metadata, and search results nest naturally as JSON documents |
| **Atlas hosting** | Fully managed cloud service with free tier; no infrastructure management |
| **Aggregation pipeline** | MongoDB's aggregation framework enables powerful analytics across investigations |
| **GridFS** | Built-in support for storing large binary files (recovered images, reports) |

**Planned Collection Schema:**

```json
// investigations collection
{
  "_id": "78b67a91",
  "evidence_name": "suspect_drive.dd",
  "evidence_type": "disk_image",
  "status": "completed",
  "progress": 100,
  "created_at": "2026-03-18T22:00:00Z",
  "hashes": {
    "md5": "abc123...",
    "sha256": "def456...",
    "sha1": "ghi789..."
  },
  "disk_results": { "partitions": [...], "deleted_files": [...] },
  "artifacts": { "browser_history": [...], "multimedia": [...] },
  "search_results": { "password": [...], "bitcoin": [...] },
  "ai_summary": "The analysis reveals...",
  "report_path": "/reports/78b67a91/report.html"
}
```

---

### 3.11 Frontend — Vanilla HTML5 / CSS3 / JavaScript

**No JavaScript Framework Used — By Design**

The frontend was intentionally built without React, Vue, or Angular. This decision was made for the following reasons:

| Reason | Detail |
|---|---|
| **Zero build step** | No webpack, Vite, or npm build process needed for the frontend |
| **Deployment simplicity** | HTML files served directly by FastAPI's StaticFiles |
| **Performance** | No framework overhead — pages load faster on slow forensic lab networks |
| **Maintainability** | Any investigator with basic web knowledge can modify the UI |
| **Self-contained reports** | Generated reports are single HTML files with no external dependencies |

**CSS Architecture:**

- **CSS Custom Properties (variables)** — Design tokens for colors, spacing, shadows
- **CSS Grid** — Features grid layout, stats row, info grid
- **CSS Flexbox** — Navigation, cards, job items, media cards
- **CSS Animations** — Progress spinner (`@keyframes spin`), status pulse (`@keyframes pulse`)
- **Responsive breakpoints**: `768px` (tablet), `600px` (phone), `480px` (small phone), `380px` (extra small)

**JavaScript Architecture:**

The frontend JavaScript follows a simple module pattern:

```javascript
// Core functions (no framework needed):
selectFile(file)        // File selection and preview
startAnalysis()         // Upload and trigger pipeline
startPolling(jobId)     // Status polling every 2.2 seconds
pollStatus(jobId)       // Fetch and update progress UI
loadJobs()              // List all investigation jobs
delJob(id)              // Delete job and its files
checkHealth()           // Check forensic tool availability
showToast(msg, type)    // Mobile-friendly notification system
scrollToUpload()        // Bottom nav helper
scrollToJobs()          // Bottom nav helper
```

---

### 3.12 Font Awesome 6 (Icons)

**Version:** 6.5.0 (CDN)  
**Role:** Icon library for UI elements

Font Awesome provides SVG-based icons that scale to any size without quality loss. Used throughout the platform for evidence type indicators, status icons, navigation items, and section headers.

```html
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
```

---

### 3.13 uvicorn (ASGI Server)

**Version:** `>=0.27.0`  
**Role:** High-performance Python ASGI server

uvicorn is the recommended production server for FastAPI applications. It is built on `uvloop` (a fast event loop replacement) and `httptools` (a fast HTTP parser), making it significantly faster than traditional WSGI servers like gunicorn.

**Performance characteristics:**
- Handles 10,000+ requests/second on modern hardware
- Native async/await support
- WebSocket support (for future real-time progress streaming)
- Hot reload in development mode

---

### 3.14 python-multipart (File Upload Parsing)

**Version:** `>=0.0.9`  
**Role:** Parsing `multipart/form-data` HTTP requests

Required by FastAPI to parse file uploads. When a user uploads an evidence file, the browser sends a `multipart/form-data` POST request containing both the file binary data and form fields (keywords). `python-multipart` handles the streaming decoding of this data.

---

### 3.15 Render.com (Deployment Platform)

**Role:** Python web service hosting

Render is a modern cloud hosting platform that supports Python web services natively. It was selected over alternatives for the following reasons:

| Platform | Python Support | Free Tier | Auto-Deploy | Always-On Free |
|---|---|---|---|---|
| **Render** | ✅ Native | ✅ Yes | ✅ GitHub push | ❌ Sleeps (free) |
| Vercel | ❌ No native Python | ✅ Yes | ✅ Yes | ✅ Yes |
| Heroku | ✅ Yes | ❌ No free | ✅ Yes | ❌ No |
| Cloudflare Workers | ❌ V8 JS only | ✅ Yes | ✅ Yes | ✅ Yes |
| Railway | ✅ Yes | Limited | ✅ Yes | ❌ No |
| AWS Lambda | ✅ Yes | Limited | ⚠️ Complex | ✅ Yes |

**Why Render Over Vercel/Cloudflare for This Project:**

Vercel and Cloudflare Workers use JavaScript/V8 runtime environments that **cannot execute Python**. This platform requires:
- Direct invocation of system tools (TSK, ExifTool) via `subprocess`
- File system access (uploading, storing, reading evidence files)
- Long-running background processes (analysis pipelines > 30 seconds)
- SQLite database access (browser history parsing)

All of these requirements are **incompatible** with serverless JavaScript platforms. Render provides a full Linux environment supporting all of these needs.

---

### 3.16 Git / GitHub (Version Control)

**Repository:** https://github.com/ayahmajali/forensic-platform  
**Role:** Source code versioning, collaboration, CI/CD trigger

Git version control enables:
- **Full commit history** — every change is tracked with author, timestamp, and description
- **Branching** — feature development in isolation from main branch
- **Auto-deployment** — Render.com monitors the `main` branch and auto-deploys on every push
- **Code review** — Pull request workflow for team collaboration
- **Rollback** — Instant revert to any previous working version

---

## 4. Core Modules

### 4.1 `analyzer.py` — Core Evidence Analyzer

**Class:** `ForensicAnalyzer`  
**Responsibility:** Evidence type detection and cryptographic hashing

**Evidence Type Detection Logic:**

```
1. Check file extension (.e01, .dd, .raw, .img, .iso, .vmdk, .vhd)
2. Read first 512 bytes (file header / magic bytes)
   - b"EVF"         → E01 (EnCase Evidence Format)
   - b"\x00CD001"   → ISO 9660 (CD/DVD image)
   - b"\x55\xaa"    → MBR signature (raw disk image)
   - b"EFI PART"    → GPT signature (modern disk image)
3. Fall back to document/logical file classification
   (.pdf, .docx, .jpg, .mp4, etc.)
```

**Key Methods:**

| Method | Returns | Description |
|---|---|---|
| `detect_evidence_type()` | `str` | Evidence type string: 'disk_image', 'e01', 'logical_file', etc. |
| `compute_hashes()` | `Dict` | MD5, SHA-1, SHA-256, file size |
| `get_file_info()` | `Dict` | Name, size, extension, path |

---

### 4.2 `disk_analysis.py` — Disk Image Analysis

**Class:** `DiskAnalyzer`  
**Responsibility:** Full disk image analysis using Sleuth Kit tools

**Key Methods:**

| Method | TSK Tool | Output |
|---|---|---|
| `run_mmls()` | `mmls` | Partition table: slot, start, end, length, offset |
| `run_fsstat()` | `fsstat` | Filesystem type, volume name, block size, inode count |
| `run_fls()` | `fls -r -m /` | All files recursively with inodes and types |
| `run_deleted_files()` | `fls -r -d` | Deleted files only |
| `run_ils()` | `ils` | All inodes (allocated + unallocated) |
| `recover_files()` | `tsk_recover` | Recovers all files to output directory |
| `run_full_disk_analysis()` | All above | Combined disk analysis report |

**Partition Offset Calculation:**

```python
# Disk images have partitions at specific sector offsets
# Each sector = 512 bytes
# fls/fsstat require byte offset to access correct partition

partition_offset = start_sector * 512  # bytes
fls_cmd = ["fls", "-r", "-o", str(partition_offset), image_path]
```

---

### 4.3 `artifact_extractor.py` — Artifact Extraction

**Class:** `ArtifactExtractor`  
**Responsibility:** Browser history, EXIF metadata, multimedia, and documents

**Extraction Categories:**

1. **Browser History** — Finds SQLite databases named `History` (Chrome) or `places.sqlite` (Firefox), queries them, and converts WebKit/Unix timestamps
2. **EXIF Metadata** — Invokes ExifTool on all image files, extracts 20+ metadata fields
3. **Multimedia Files** — Classifies recovered files by extension into images/videos, prepares paths for HTML preview
4. **Documents** — Identifies PDF, DOCX, XLSX, TXT files for listing in report
5. **Media Carving** — Optionally invokes PhotoRec or Foremost for deep binary carving of deleted media

**WebKit Timestamp Conversion:**

```python
# Chrome stores timestamps as microseconds since Jan 1, 1601
WEBKIT_EPOCH_DELTA = 11644473600  # seconds between 1601 and 1970

def _webkit_to_datetime(self, webkit_ts: int) -> str:
    unix_ts = (webkit_ts / 1_000_000) - WEBKIT_EPOCH_DELTA
    return datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S")
```

---

### 4.4 `timeline_builder.py` — Forensic Timeline

**Class:** `TimelineBuilder`  
**Responsibility:** MAC-time activity timeline generation

**MAC Time Definition:**

| Letter | Meaning | Description |
|---|---|---|
| **M** | Modified | File content last changed |
| **A** | Accessed | File last read/opened |
| **C** | Changed | File metadata (permissions, owner) changed |
| **B** | Born | File creation time (NTFS/HFS+ only) |

**Timeline Generation Process:**

```
1. Run: fls -r -m "/" -o {offset} {image}
   → Generates body file in mactime format:
     MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime

2. Run: mactime -b {bodyfile} -d
   → Sorts all events chronologically
   → Output: Date, Size, Activity, Permissions, Inode, File

3. Parse mactime output → List of timeline events
4. Fallback: If TSK unavailable, use os.stat() on recovered files
```

**Fallback Timeline (No TSK):**

```python
# Uses Python's os.stat() to build timeline from recovered files
for fpath in recovered_path.rglob("*"):
    stat = fpath.stat()
    events.append({
        "date": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "activity": "M",
        "filename": str(fpath.relative_to(recovered_path)),
        "size": stat.st_size,
    })
```

---

### 4.5 `keyword_search.py` — Forensic Keyword Search Engine

**Class:** `KeywordSearchEngine`  
**Responsibility:** Deep keyword search across all evidence artifacts

**Search Domains:**

| Domain | Method | What It Searches |
|---|---|---|
| **Filenames** | `search_filenames()` | File names and extensions |
| **File Content** | `search_file_content()` | Text files: .txt, .log, .csv, .json, .py, .sql, etc. |
| **Browser History** | `search_browser_history()` | URLs and page titles |
| **Metadata** | `search_metadata()` | EXIF fields (camera model, GPS, software) |
| **Strings** | `search_strings()` | Printable ASCII strings extracted from binary files |

**Pattern Matching:**

```python
# Regex-based search for sophisticated patterns
EMAIL_PATTERN    = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
URL_PATTERN      = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
BITCOIN_PATTERN  = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
CREDIT_CARD_PAT  = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
```

**Search Result Schema:**

```python
{
    "match_type": "content",        # filename|content|browser_history|metadata
    "keyword": "password",
    "file": "recovered/documents/passwords.txt",
    "context": "admin_password=SecretPass123",  # Surrounding text
    "line_number": 42,
    "source": "filesystem"
}
```

---

### 4.6 `ai_summary.py` — AI Evidence Summarization

**Class:** `AISummarizer`  
**Responsibility:** OpenAI GPT-powered forensic narrative generation

**Two-tier Operation:**

```
Tier 1: OpenAI API Available
├── Build structured prompt with all findings
├── Call gpt-4o-mini API
└── Return professional markdown summary

Tier 2: OpenAI Unavailable (graceful fallback)
├── Use template-based summary generation
└── Return structured markdown from Python f-strings
```

**Output Format:** Markdown with sections:
- Executive Summary
- Evidence Overview  
- Key Findings
- Deleted File Analysis
- Browser Activity
- Suspicious Keywords
- Investigator Recommendations

---

### 4.7 `report_generator.py` — Interactive HTML Report Generator

**Class:** `ReportGenerator`  
**Responsibility:** Self-contained interactive HTML forensic report generation

This is the most complex module at 1,274 lines. It generates a complete standalone HTML file containing all forensic findings with an interactive UI.

**Report Sections:**

| Section | Content |
|---|---|
| **AI Summary** | GPT-generated or template markdown summary |
| **Evidence Information** | Filename, type, size, analysis date |
| **Hash Values** | MD5, SHA-1, SHA-256 for chain of custody |
| **Statistics Row** | Counts of files, deleted files, images, videos, documents, browser entries |
| **Disk Partitions** | mmls output: slot, start, end, length, offset, description |
| **Filesystem Info** | fsstat output: type, volume name, block size, block count |
| **All Files Table** | Complete file listing with type, name, inode, status |
| **Deleted Files Table** | Highlighted deleted files (red background) |
| **Multimedia Preview** | Image gallery with lightbox, video player |
| **Documents List** | PDF, DOCX, XLSX with icons |
| **Browser History** | Chrome/Firefox URLs, titles, timestamps |
| **EXIF Metadata** | Camera info, GPS with Google Maps link |
| **Forensic Timeline** | MAC-time sorted activity log |
| **Keyword Search Results** | Hits grouped by keyword with context |

**Mobile-Responsive Report Features:**
- Off-canvas sidebar drawer with hamburger button (≤900px)
- Horizontal table scroll with touch support
- 2-column stats grid on phones
- Near-fullscreen image lightbox on mobile
- Auto-close navigation drawer after section selection

---

## 5. Forensic Analysis Pipeline

### 5.1 Pipeline Overview

The analysis pipeline is executed as a FastAPI `BackgroundTask`, allowing the HTTP server to remain responsive while analysis runs.

```
Evidence Upload
     │
     ▼ Step 1 (5-10%)
┌─────────────────────┐
│  Evidence Detection  │  detect_evidence_type()
│  + Hash Computation  │  compute_hashes()
└─────────┬───────────┘
          │ type: disk_image?
    ┌─────┴─────┐
   YES          NO
    │            │
    ▼            ▼
Step 2 (15-45%)  Step 3 (45%)
┌──────────────┐  ┌─────────────────┐
│ Disk Analysis│  │ Copy to recovered│
│ mmls, fsstat │  │ directory        │
│ fls, ils     │  └────────┬────────┘
│ tsk_recover  │           │
└──────┬───────┘           │
       └──────────┬────────┘
                  │
                  ▼ Step 4 (45-60%)
         ┌────────────────────┐
         │  Artifact Extraction│
         │  Browser History   │
         │  EXIF Metadata     │
         │  Multimedia Files  │
         │  Documents         │
         └────────┬───────────┘
                  │
                  ▼ Step 5 (60-70%)
         ┌────────────────────┐
         │  Timeline Builder  │
         │  fls + mactime     │
         │  MAC-time events   │
         └────────┬───────────┘
                  │
                  ▼ Step 6 (70-80%)
         ┌────────────────────┐
         │  Keyword Search    │
         │  filenames/content │
         │  browser/metadata  │
         └────────┬───────────┘
                  │
                  ▼ Step 7 (80-88%)
         ┌────────────────────┐
         │  AI Summarization  │
         │  GPT-4o-mini API   │
         │  (or fallback)     │
         └────────┬───────────┘
                  │
                  ▼ Step 8 (88-100%)
         ┌────────────────────┐
         │  Report Generation │
         │  HTML + CSS + JS   │
         │  Self-contained    │
         └────────────────────┘
                  │
                  ▼
         report.html ready
         GET /api/report-file/{job_id}
```

### 5.2 Evidence Type Decision Matrix

| Evidence Type | Disk Analysis | File Recovery | Artifact Extraction | Timeline |
|---|---|---|---|---|
| E01 (EnCase) | ✅ Full | ✅ tsk_recover | ✅ Full | ✅ fls+mactime |
| DD / RAW | ✅ Full | ✅ tsk_recover | ✅ Full | ✅ fls+mactime |
| ISO Image | ✅ Full | ✅ tsk_recover | ✅ Full | ✅ fls+mactime |
| IMG | ✅ Full | ✅ tsk_recover | ✅ Full | ✅ fls+mactime |
| Logical File | ❌ Skip | ✅ Copy | ✅ If applicable | ✅ Filesystem stat |

---

## 6. API Reference

### Base URL
```
Local:      http://localhost:8000
Production: https://forensic-platform.onrender.com
```

### Endpoints

#### `POST /api/investigate`
Upload evidence and start forensic analysis.

**Request:** `multipart/form-data`

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence` | File | ✅ | Evidence file (any format) |
| `keywords` | String | ❌ | Comma-separated keywords (default: "password,login,bitcoin,admin,secret,gmail,exe,pdf") |

**Response:** `200 OK`
```json
{
  "job_id": "78b67a91",
  "status": "queued",
  "message": "Investigation started"
}
```

---

#### `GET /api/status/{job_id}`
Poll analysis progress and status.

**Response:** `200 OK`
```json
{
  "job_id": "78b67a91",
  "status": "running",          // queued|running|completed|failed
  "progress": 65,               // 0-100
  "evidence_name": "disk.dd",
  "evidence_type": "disk_image",
  "log": ["[22:00:01] Step 1: Detecting evidence type..."],
  "report_url": "/api/report-file/78b67a91",
  "recovered_count": 1247,
  "hashes": {
    "md5": "abc123...",
    "sha256": "def456...",
    "sha1": "ghi789..."
  }
}
```

---

#### `GET /api/report-file/{job_id}`
Retrieve the completed interactive HTML report.

**Response:** `200 OK` — `text/html` — Full self-contained HTML report

---

#### `GET /api/jobs`
List all investigation jobs.

**Response:** `200 OK`
```json
{
  "jobs": [
    {
      "job_id": "78b67a91",
      "evidence_name": "disk.dd",
      "status": "completed",
      "progress": 100,
      "created_at": "2026-03-18T22:00:00",
      "report_url": "/api/report-file/78b67a91",
      "evidence_type": "disk_image"
    }
  ]
}
```

---

#### `POST /api/search/{job_id}`
Run dynamic keyword search on completed analysis.

**Request:** `application/json`
```json
{ "keyword": "bitcoin" }
```

**Response:** `200 OK`
```json
{
  "keyword": "bitcoin",
  "results": [
    {
      "match_type": "content",
      "file": "documents/wallet.txt",
      "context": "bitcoin address: 1A2B3C...",
      "line_number": 15
    }
  ]
}
```

---

#### `DELETE /api/jobs/{job_id}`
Delete investigation job and all associated files.

**Response:** `200 OK`
```json
{ "message": "Job deleted successfully" }
```

---

#### `POST /api/config/openai`
Configure OpenAI API key at runtime.

**Request:** `application/json`
```json
{ "key": "sk-proj-..." }
```

---

#### `GET /api/health`
System health check and tool availability.

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "tools": {
    "mmls": false,
    "fsstat": false,
    "fls": false,
    "ils": false,
    "tsk_recover": false,
    "exiftool": false,
    "photorec": false,
    "foremost": false
  },
  "timestamp": "2026-03-18T22:00:00"
}
```

---

## 7. Frontend Design & UI/UX

### 7.1 Design Philosophy

The frontend was designed around three principles:

1. **Clarity**: Forensic data can be overwhelming — the UI prioritizes progressive disclosure (summary first, details on demand)
2. **Professionalism**: Clean light theme suitable for courtroom presentations and professional reports
3. **Accessibility**: Mobile-first responsive design ensures the platform is usable on tablets in field investigations

### 7.2 Design System

**Color Palette:**

| Token | Value | Usage |
|---|---|---|
| `--primary` | `#2563eb` | Primary actions, links, active states |
| `--primary-dark` | `#1d4ed8` | Button hover states |
| `--primary-light` | `#eff6ff` | Light backgrounds, selected states |
| `--bg` | `#f0f4f8` | Page background |
| `--surface` | `#ffffff` | Cards, nav, sidebar |
| `--border` | `#e2e8f0` | Dividers, card borders |
| `--text` | `#1e293b` | Primary text |
| `--text-muted` | `#64748b` | Secondary text, labels |
| `--success` | `#16a34a` | Completed states, hashes |
| `--danger` | `#dc2626` | Deleted files, errors |
| `--warning` | `#d97706` | Running states, warnings |
| `--purple` | `#7c3aed` | AI features, gradient |

### 7.3 Responsive Breakpoints

| Breakpoint | Screen Size | Changes Applied |
|---|---|---|
| Desktop | > 768px | Full sidebar, all elements visible |
| Tablet | ≤ 768px | Icon-only nav buttons, stacked job actions |
| Phone | ≤ 600px | Bottom navigation bar, condensed upload area |
| Small Phone | ≤ 480px | Reduced font sizes, form inputs 16px (iOS zoom prevention) |
| Extra Small | ≤ 380px | Minimal padding, 2-column grids only |

### 7.4 Report UI Components

**Left Sidebar Navigation:**
- Fixed position during scrolling
- 12 section links with icons
- Active section highlighted via scroll spy
- On mobile (≤900px): Off-canvas drawer with hamburger button, overlay backdrop, auto-close on navigation

**Global Search Bar:**
- Real-time client-side search across filenames and browser history
- Keyboard shortcut: Enter to search
- Dismisses on outside click

**Image Lightbox:**
- Click-to-expand for all recovered images
- Video player for recovered video files
- Keyboard Escape to close
- Near-fullscreen on mobile devices

**Interactive Tables:**
- Live keyword filter on All Files, Deleted Files, Browser History, Timeline tables
- Horizontal scroll on mobile with `-webkit-overflow-scrolling: touch`
- Deleted rows highlighted in red

---

## 8. Database & Storage Architecture

### 8.1 File System Storage (Runtime)

During analysis, the platform uses a structured directory layout:

```
/tmp/forensic/                    (Render/Vercel writable root)
├── uploads/
│   └── {job_id}_{filename}       Original evidence file
├── recovered/
│   └── {job_id}/                 Recovered files from tsk_recover
│       ├── img0/                 Partition 0 files
│       ├── img1/                 Partition 1 files
│       └── timeline.body         fls body file for mactime
└── reports/
    └── {job_id}/
        └── report.html           Self-contained HTML report
```

### 8.2 MongoDB Collections

```
forensic_db
├── investigations    — Job metadata, status, progress
├── reports          — Report content and paths
├── artifacts        — Extracted browser history, metadata, files
└── search_results   — Keyword search hit records
```

### 8.3 Evidence Integrity Flow

```
1. User uploads evidence file
2. Platform immediately computes MD5, SHA-1, SHA-256
3. Hashes stored in job record
4. Analysis pipeline reads but NEVER modifies the original file
5. tsk_recover creates copies — original evidence untouched
6. Hashes displayed in final report for chain of custody verification
```

---

## 9. Security & Chain of Custody

### 9.1 Evidence Integrity

- **Read-only access**: The original evidence file is never modified by any analysis step
- **Hash verification**: MD5, SHA-1, SHA-256 computed immediately on upload and displayed in all reports
- **Isolated directories**: Each job gets a unique UUID-based directory preventing cross-contamination

### 9.2 API Security

- **CORS policy**: Currently permissive (`*`) — production deployment should restrict to known origins
- **Input sanitization**: All user inputs and file names are HTML-escaped using Python's `html.escape()` before inclusion in reports
- **File type validation**: Magic byte detection prevents misclassification of files
- **Path traversal prevention**: `pathlib.Path` and `.relative_to()` prevent directory traversal attacks

### 9.3 Data Privacy

- Evidence files are stored only in the `/tmp` directory and never committed to version control
- `.gitignore` and `.vercelignore` exclude `uploads/`, `reports/`, and `recovered/` directories
- OpenAI API calls include only metadata summaries, never raw file content — protecting evidence confidentiality

---

## 10. Deployment Architecture

### 10.1 Development Environment

```
Local Machine
├── Python 3.11 + pip
├── The Sleuth Kit (installed via package manager)
├── ExifTool (installed via package manager)
├── PM2 (process manager, pre-installed in sandbox)
└── uvicorn (starts automatically via PM2)

Start: pm2 start ecosystem.config.cjs
URL:   http://localhost:8000
```

### 10.2 Production Environment (Render.com)

```yaml
# render.yaml
services:
  - type: web
    name: forensic-platform
    runtime: python
    rootDir: backend
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: OPENAI_API_KEY
      - key: MONGODB_URI
```

**Render.com Deployment Flow:**

```
GitHub Push (main branch)
        │
        ▼
Render detects change
        │
        ▼
Build: pip install -r backend/requirements.txt
        │
        ▼
Start: uvicorn main:app --host 0.0.0.0 --port $PORT
        │
        ▼
Health check: GET /api/health → 200 OK
        │
        ▼
Live: https://forensic-platform.onrender.com
```

### 10.3 Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Optional | GPT-4o-mini API key for AI summaries |
| `MONGODB_URI` | Optional | MongoDB Atlas connection string |
| `PORT` | Auto-set | Listening port (set by Render) |
| `VERCEL` | Dev only | Enables Vercel-specific file paths |

---

## 11. Testing Strategy

### 11.1 Manual Testing Checklist

**Health Check:**
```bash
curl https://forensic-platform.onrender.com/api/health
# Expected: {"status":"healthy","tools":{...}}
```

**Evidence Upload & Analysis:**
```bash
# Create test evidence
echo "Test: password=abc123 bitcoin wallet admin@gmail.com" > test.txt

# Upload and analyze
curl -X POST https://forensic-platform.onrender.com/api/investigate \
  -F "evidence=@test.txt" \
  -F "keywords=password,bitcoin,gmail,admin"

# Check status
curl https://forensic-platform.onrender.com/api/status/{job_id}

# View report
open https://forensic-platform.onrender.com/api/report-file/{job_id}
```

**Keyword Search:**
```bash
curl -X POST https://forensic-platform.onrender.com/api/search/{job_id} \
  -H "Content-Type: application/json" \
  -d '{"keyword": "password"}'
```

### 11.2 Test Evidence Types

| Test File | Expected Behavior |
|---|---|
| `.txt` with keywords | Keyword hits in content search |
| `.jpg` with GPS EXIF | GPS coordinates in metadata section |
| Chrome `History` SQLite | Browser history entries populated |
| Firefox `places.sqlite` | Firefox history entries populated |
| `.dd` disk image (with TSK) | Partition table, file listing, deleted files |
| `.iso` image (with TSK) | ISO 9660 filesystem analysis |

### 11.3 Automated Tests

```python
# backend/tests/test_api.py
import pytest
from httpx import AsyncClient
from main import app

@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_investigate_logical_file(tmp_path):
    evidence = tmp_path / "test.txt"
    evidence.write_text("password bitcoin gmail admin secret")
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/api/investigate",
            files={"evidence": ("test.txt", evidence.read_bytes(), "text/plain")},
            data={"keywords": "password,bitcoin"}
        )
    assert response.status_code == 200
    assert "job_id" in response.json()
```

**Run Tests:**
```bash
cd backend
pip install pytest pytest-asyncio httpx
pytest tests/ -v --asyncio-mode=auto
```

---

## 12. Project Structure

```
forensic-platform/
│
├── index.py                    # Root Vercel serverless entry (legacy)
├── requirements.txt            # Root-level Python dependencies
├── runtime.txt                 # Python version: python-3.11.0
├── Procfile                    # Heroku/Render process definition
├── render.yaml                 # Render.com deployment configuration
├── vercel.json                 # Vercel deployment config (legacy)
├── ecosystem.config.cjs        # PM2 process manager config (dev)
├── .gitignore                  # Git ignore (node_modules, uploads, etc.)
├── .vercelignore               # Vercel deploy ignore
├── README.md                   # Quick-start guide
├── DOCUMENTATION.md            # This file — full technical documentation
│
├── api/
│   ├── index.py                # Vercel API entrypoint (legacy)
│   └── requirements.txt        # Vercel dependencies (legacy)
│
└── backend/
    ├── main.py                 # FastAPI application, routes, pipeline orchestration
    ├── start.py                # Development startup script with env loading
    ├── requirements.txt        # Python dependencies for Render/local
    │
    ├── modules/
    │   ├── __init__.py
    │   ├── analyzer.py         # Evidence type detection + hash computation
    │   ├── disk_analysis.py    # Sleuth Kit integration (mmls/fsstat/fls/tsk_recover)
    │   ├── artifact_extractor.py # Browser history + EXIF + multimedia extraction
    │   ├── timeline_builder.py # MAC-time forensic timeline generation
    │   ├── keyword_search.py   # Keyword search across all evidence artifacts
    │   ├── ai_summary.py       # OpenAI GPT-4o-mini summarization
    │   └── report_generator.py # Interactive HTML report generation (1274 lines)
    │
    ├── templates/
    │   └── index.html          # Main web UI (upload, progress, jobs)
    │
    ├── static/
    │   └── css/
    │       └── custom.css      # Custom CSS overrides
    │
    ├── uploads/                # Evidence files (gitignored)
    ├── reports/                # Generated HTML reports (gitignored)
    └── recovered/              # tsk_recover output (gitignored)
```

---

## 13. Limitations & Future Work

### 13.1 Current Limitations

| Limitation | Description | Mitigation |
|---|---|---|
| **TSK not on server** | Sleuth Kit not installed on Render free tier | Use local installation or Docker |
| **ExifTool not on server** | ExifTool CLI not pre-installed | Install via apt in Render build command |
| **In-memory job store** | Jobs lost on server restart | MongoDB integration (in progress) |
| **No authentication** | Any user can access any investigation | Add JWT authentication |
| **Single-threaded analysis** | One analysis at a time per worker | Add Celery task queue |
| **File size limits** | Large disk images impractical in browser | Direct S3/R2 upload bypass |
| **No encryption** | Evidence stored unencrypted | Add AES-256 at-rest encryption |

### 13.2 Recommended Future Enhancements

1. **Docker containerization** — Package Sleuth Kit and ExifTool in Docker image for consistent deployment
2. **Celery + Redis task queue** — Handle multiple concurrent investigations with worker pools
3. **User authentication** — JWT-based login with role-based access (investigator, reviewer, admin)
4. **Case management** — Group multiple evidence files into investigation cases
5. **Network forensics** — PCAP analysis with Wireshark/tshark integration
6. **Memory forensics** — Volatility Framework integration for RAM image analysis
7. **Registry analysis** — Windows Registry hive parsing
8. **Encrypted evidence** — Support for BitLocker/LUKS encrypted disk images
9. **Chain of custody log** — Immutable audit trail of all actions taken on evidence
10. **Collaborative review** — Multi-investigator annotation and comments on findings
11. **Machine learning** — Anomaly detection for unusual file access patterns in timelines

---

## 14. References

1. Carrier, B. (2005). *File System Forensic Analysis*. Addison-Wesley Professional. — Foundational reference for Sleuth Kit design
2. Casey, E. (2011). *Digital Evidence and Computer Crime* (3rd ed.). Academic Press.
3. Nelson, B., Phillips, A., & Steuart, C. (2014). *Guide to Computer Forensics and Investigations* (5th ed.). Cengage Learning.
4. The Sleuth Kit Documentation: https://www.sleuthkit.org/sleuthkit/docs.php
5. ExifTool Documentation: https://exiftool.org/ExifTool_pod.html
6. FastAPI Documentation: https://fastapi.tiangolo.com
7. NIST Special Publication 800-86: *Guide to Integrating Forensic Techniques into Incident Response* (2006)
8. SWGDE Best Practices for Computer Forensics: https://www.swgde.org
9. RFC 3227: *Guidelines for Evidence Collection and Archiving* (2002)
10. OpenAI API Documentation: https://platform.openai.com/docs
11. MongoDB Atlas Documentation: https://www.mongodb.com/docs/atlas
12. Render.com Documentation: https://render.com/docs
13. Harvey, P. (2022). ExifTool Application Documentation. CPAN.
14. Pydantic Documentation: https://docs.pydantic.dev
15. Python 3.11 Release Notes: https://docs.python.org/3.11/whatsnew/3.11.html

---

*Documentation generated: March 2026*  
*Platform version: 1.0.0*  
*Author: Ayah Majali*  
*Project: Digital Forensics Investigation Platform — Graduate Research*
