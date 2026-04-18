"""
Digital Forensics Investigation Platform
Main FastAPI Application Entry Point
Works on: local dev, PM2, AND Vercel serverless
"""

import os
import sys
import uuid
import json
import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.requests import Request
from fastapi.middleware.cors import CORSMiddleware
import aiofiles

# ── Ensure backend dir is always on the path (needed when called from api/index.py) ──
_THIS_DIR = Path(__file__).parent.resolve()
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

# Import modules
from modules.analyzer import ForensicAnalyzer
from modules.disk_analysis import DiskAnalyzer
from modules.artifact_extractor import ArtifactExtractor
from modules.timeline_builder import TimelineBuilder
from modules.keyword_search import KeywordSearchEngine
from modules.report_generator import ReportGenerator
from modules.ai_summary import AISummarizer
from modules.database import case_store
from modules.auth import require_agent_api_key
from modules.pdf_report import generate_pdf_report

# ─────────────────────────────────────────
# Path Configuration
# Works for local server AND Vercel serverless
# Vercel uses /tmp for writable storage (read-only filesystem otherwise)
# ─────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR  = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# On Vercel (read-only filesystem) we use /tmp; everywhere else write next to main.py
IS_VERCEL = os.getenv("VERCEL", "") == "1" or os.getenv("VERCEL_ENV", "") != ""
IS_RENDER = os.getenv("RENDER", "") != ""

if IS_VERCEL:
    _WRITABLE = Path(tempfile.gettempdir()) / "forensic"
else:
    _WRITABLE = BASE_DIR

UPLOAD_DIR    = _WRITABLE / "uploads"
REPORTS_DIR   = _WRITABLE / "reports"
RECOVERED_DIR = _WRITABLE / "recovered"

for d in [UPLOAD_DIR, REPORTS_DIR, RECOVERED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Digital Forensics Investigation Platform",
    description="Professional forensic investigation system for disk images and logical files",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (always available — they're in the repo)
try:
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
except Exception as e:
    print(f"[WARN] Could not mount /static: {e}")

# Mount reports and recovered — always available on local/Render
# Skip empty-dir check; just wrap in try/except so cold start never crashes
for _mount_path, _mount_dir, _mount_name in [
    ("/reports",   REPORTS_DIR,   "reports"),
    ("/recovered", RECOVERED_DIR, "recovered"),
]:
    try:
        _mount_dir.mkdir(parents=True, exist_ok=True)
        # Create a .keep file so StaticFiles doesn't crash on empty dir
        _keep = _mount_dir / ".keep"
        if not _keep.exists():
            _keep.write_text("")
        app.mount(_mount_path, StaticFiles(directory=str(_mount_dir)), name=_mount_name)
    except Exception as e:
        print(f"[WARN] Could not mount {_mount_path}: {e}")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ─────────────────────────────────────────
# Case / Job Store
# ─────────────────────────────────────────
# `investigation_jobs` is kept as a fast in-memory cache that the hot code-path
# already depends on. Every mutation is mirrored to MongoDB (or the in-memory
# fallback inside case_store) so cases survive a restart.
investigation_jobs: dict = {}


def _persist_job(job_id: str) -> None:
    """Mirror the current in-memory job dict to the persistent case store."""
    job = investigation_jobs.get(job_id)
    if job is None:
        return
    try:
        case_store.save_case(job_id, job)
    except Exception as e:  # persistence must never crash the pipeline
        print(f"[DB] _persist_job({job_id}) failed: {e}")


def _patch_job(job_id: str, patch: dict) -> None:
    """Merge-patch a job, updating memory + DB in one call."""
    if job_id not in investigation_jobs:
        return
    investigation_jobs[job_id].update(patch)
    try:
        case_store.update_case(job_id, patch)
    except Exception as e:
        print(f"[DB] _patch_job({job_id}) failed: {e}")


# ─────────────────────────────────────────
# Background Analysis Task
# ─────────────────────────────────────────
async def run_full_analysis(job_id: str, evidence_path: Path, evidence_name: str, keywords: list):
    """Full forensic analysis pipeline running in the background."""
    job = investigation_jobs[job_id]
    job["status"] = "running"
    job["progress"] = 5
    job["log"] = []
    _persist_job(job_id)

    def log(msg: str):
        job["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        print(f"[Job {job_id}] {msg}")

    try:
        log("Starting forensic analysis pipeline...")
        recovered_path = RECOVERED_DIR / job_id
        recovered_path.mkdir(parents=True, exist_ok=True)

        # Step 1: Evidence Type Detection
        log("Step 1: Detecting evidence type...")
        analyzer = ForensicAnalyzer(str(evidence_path))
        evidence_type = analyzer.detect_evidence_type()
        job["progress"] = 10
        job["evidence_type"] = evidence_type
        log(f"Evidence type detected: {evidence_type}")

        # Step 2: Hashing
        log("Step 2: Computing evidence hashes (MD5, SHA256)...")
        hashes = analyzer.compute_hashes()
        job["hashes"] = hashes
        job["progress"] = 15
        log(f"SHA256: {hashes.get('sha256', 'N/A')}")

        # Step 3: Disk Analysis (if disk image)
        disk_results = {}
        partition_offset = 0
        if evidence_type in ["disk_image", "e01", "dd", "raw", "img", "iso"]:
            log("Step 3: Running Sleuth Kit disk analysis...")
            disk_analyzer = DiskAnalyzer(str(evidence_path))
            disk_results = disk_analyzer.run_full_disk_analysis()
            partition_offset = disk_results.get("offset", 0)
            job["disk_results"] = disk_results
            job["progress"] = 30
            log(f"Partitions found: {len(disk_results.get('partitions', []))}")

            # File Recovery
            log("Step 3b: Recovering files with tsk_recover...")
            recovered_files = disk_analyzer.recover_files(str(recovered_path), partition_offset)
            job["recovered_count"] = len(recovered_files)
            job["progress"] = 45
            log(f"Recovered {len(recovered_files)} files")
        else:
            log("Step 3: Logical file analysis (skipping disk imaging steps)...")
            # Copy logical file to recovered
            shutil.copy2(str(evidence_path), str(recovered_path / evidence_name))
            job["disk_results"] = {}
            job["recovered_count"] = 1
            job["progress"] = 45

        # Step 4: Artifact Extraction
        log("Step 4: Extracting artifacts (browser history, metadata, multimedia)...")
        extractor = ArtifactExtractor(str(recovered_path), str(evidence_path))
        artifacts = extractor.extract_all()
        job["artifacts"] = artifacts
        job["progress"] = 60
        log(f"Browser history entries: {len(artifacts.get('browser_history', []))}")
        log(f"Multimedia files: {len(artifacts.get('multimedia', []))}")
        log(f"Documents: {len(artifacts.get('documents', []))}")

        # Step 5: Timeline
        log("Step 5: Building forensic timeline...")
        timeline_builder = TimelineBuilder(str(evidence_path), str(recovered_path))
        timeline = timeline_builder.build_timeline()
        job["timeline"] = timeline
        job["progress"] = 70
        log(f"Timeline events: {len(timeline)}")

        # Step 6: Keyword Search
        log("Step 6: Running keyword search...")
        search_engine = KeywordSearchEngine(str(recovered_path), artifacts)
        search_results = search_engine.search_all(keywords)
        job["search_results"] = search_results
        job["progress"] = 80
        log(f"Keyword hits: {sum(len(v) for v in search_results.values())}")

        # Step 7: AI Summary
        log("Step 7: Generating AI evidence summary...")
        try:
            summarizer = AISummarizer()
            ai_summary = summarizer.generate_summary({
                "evidence_name": evidence_name,
                "evidence_type": evidence_type,
                "hashes": hashes,
                "disk_results": disk_results,
                "artifacts": artifacts,
                "timeline_count": len(timeline),
                "search_results": search_results,
                "recovered_count": job.get("recovered_count", 0)
            })
        except Exception as e:
            log(f"AI summary skipped: {e}")
            ai_summary = generate_local_summary(evidence_name, evidence_type, artifacts, 
                                                  disk_results, search_results, job)
        job["ai_summary"] = ai_summary
        job["progress"] = 88

        # Step 8: Report Generation
        log("Step 8: Generating interactive HTML report...")
        report_gen = ReportGenerator(
            job_id=job_id,
            evidence_name=evidence_name,
            evidence_type=evidence_type,
            hashes=hashes,
            disk_results=disk_results,
            artifacts=artifacts,
            timeline=timeline,
            search_results=search_results,
            ai_summary=ai_summary,
            recovered_path=str(recovered_path),
            reports_dir=str(REPORTS_DIR)
        )
        report_path = report_gen.generate()
        job["report_path"] = str(report_path)
        # Use /api/report-file/ route — works on both local and Vercel
        job["report_url"] = f"/api/report-file/{job_id}"
        job["progress"] = 100
        job["status"] = "completed"
        job["completed_at"] = datetime.now().isoformat()
        log("✅ Analysis complete! Report ready.")
        _persist_job(job_id)

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        job["status"] = "failed"
        job["error"] = str(e)
        job["traceback"] = tb
        log(f"❌ Analysis failed: {e}")
        print(tb)
        _persist_job(job_id)


def generate_local_summary(evidence_name, evidence_type, artifacts, disk_results, search_results, job):
    """Fallback local summary when OpenAI is unavailable."""
    multimedia = artifacts.get("multimedia", [])
    images = [f for f in multimedia if f.get("type") == "image"]
    videos = [f for f in multimedia if f.get("type") == "video"]
    docs = artifacts.get("documents", [])
    browser = artifacts.get("browser_history", [])
    deleted = disk_results.get("deleted_files", [])
    metadata = artifacts.get("metadata", [])

    suspicious = []
    for kw, hits in search_results.items():
        if hits:
            suspicious.append(f"'{kw}' ({len(hits)} hits)")

    summary = f"""## Investigation Summary — {evidence_name}

**Evidence Type:** {evidence_type.upper()}  
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Recovered Evidence
- **{job.get('recovered_count', 0)}** total files recovered
- **{len(images)}** image files found
- **{len(videos)}** video files found  
- **{len(docs)}** document files found

### Deleted Files
- **{len(deleted)}** deleted files detected — these may be significant artifacts

### Browser Artifacts
- **{len(browser)}** browser history entries found
- Domains and URLs extracted for investigation

### Metadata Highlights
- **{len(metadata)}** files with EXIF/metadata
- GPS coordinates, camera info, and timestamps extracted where available

### Keyword Search Findings
{('- Suspicious items: ' + ', '.join(suspicious)) if suspicious else '- No suspicious keywords flagged'}

### Investigator Notes
This evidence has been fully processed through the forensic pipeline. Review the detailed 
sections below for complete findings. Pay particular attention to deleted files and browser 
history for potential evidence of user activity.
"""
    return summary


# ─────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Starlette >=0.29 changed TemplateResponse's signature: the Request must
    # be the first positional argument now, not a key in the context dict.
    # The old (name, {"request": ...}) form raises TypeError: unhashable dict.
    return templates.TemplateResponse(request, "index.html")


@app.post("/api/investigate")
async def start_investigation(
    background_tasks: BackgroundTasks,
    evidence: UploadFile = File(...),
    keywords: str = Form(default="password,login,bitcoin,admin,secret,gmail,exe,pdf")
):
    """Upload evidence and start forensic analysis."""
    job_id = str(uuid.uuid4())[:8]
    
    # Save uploaded file
    safe_name = evidence.filename.replace(" ", "_")
    evidence_path = UPLOAD_DIR / f"{job_id}_{safe_name}"
    
    async with aiofiles.open(str(evidence_path), 'wb') as f:
        content = await evidence.read()
        await f.write(content)
    
    kw_list = [k.strip() for k in keywords.split(",") if k.strip()]
    
    investigation_jobs[job_id] = {
        "job_id": job_id,
        "case_id": job_id,  # alias — matches the spec's "case_id" naming
        "evidence_name": evidence.filename,
        "evidence_path": str(evidence_path),
        "status": "queued",
        "progress": 0,
        "created_at": datetime.now().isoformat(),
        "log": [],
        "keywords": kw_list,
        "source": "web",
    }
    _persist_job(job_id)

    background_tasks.add_task(
        run_full_analysis, job_id, evidence_path, evidence.filename, kw_list
    )

    return JSONResponse({
        "job_id": job_id,
        "case_id": job_id,
        "status": "queued",
        "message": "Investigation started",
    })


@app.get("/api/status/{job_id}")
async def get_job_status(job_id: str):
    """Get current status and progress of a forensic job."""
    if job_id not in investigation_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = investigation_jobs[job_id]
    return JSONResponse({
        "job_id": job_id,
        "status": job["status"],
        "progress": job["progress"],
        "evidence_name": job.get("evidence_name"),
        "evidence_type": job.get("evidence_type", "detecting..."),
        "log": job.get("log", [])[-20:],  # Last 20 log entries
        "report_url": job.get("report_url"),
        "error": job.get("error"),
        "hashes": job.get("hashes", {}),
        "recovered_count": job.get("recovered_count", 0),
    })


@app.get("/api/jobs")
async def list_jobs():
    """List all investigation jobs."""
    jobs_list = []
    for jid, job in investigation_jobs.items():
        jobs_list.append({
            "job_id": jid,
            "evidence_name": job.get("evidence_name"),
            "status": job["status"],
            "progress": job["progress"],
            "created_at": job.get("created_at"),
            "report_url": job.get("report_url"),
            "evidence_type": job.get("evidence_type", "unknown"),
        })
    return JSONResponse({"jobs": sorted(jobs_list, key=lambda x: x["created_at"], reverse=True)})


@app.get("/api/report/{job_id}")
async def get_report_data(job_id: str):
    """Get full report data as JSON."""
    if job_id not in investigation_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = investigation_jobs[job_id]
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not complete")
    return JSONResponse({
        "job_id": job_id,
        "evidence_name": job.get("evidence_name"),
        "evidence_type": job.get("evidence_type"),
        "hashes": job.get("hashes", {}),
        "disk_results": job.get("disk_results", {}),
        "artifacts": job.get("artifacts", {}),
        "timeline": job.get("timeline", [])[:100],
        "search_results": job.get("search_results", {}),
        "ai_summary": job.get("ai_summary", ""),
        "report_url": job.get("report_url"),
    })


@app.post("/api/search/{job_id}")
async def search_evidence(job_id: str, query: dict):
    """Run a dynamic keyword search on completed analysis."""
    if job_id not in investigation_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = investigation_jobs[job_id]
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not complete")
    
    keyword = query.get("keyword", "").strip()
    if not keyword:
        raise HTTPException(status_code=400, detail="Keyword required")
    
    artifacts = job.get("artifacts", {})
    recovered_path = str(RECOVERED_DIR / job_id)
    
    engine = KeywordSearchEngine(recovered_path, artifacts)
    results = engine.search_all([keyword])
    
    return JSONResponse({"keyword": keyword, "results": results.get(keyword, [])})


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete an investigation job and its files."""
    if job_id not in investigation_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Clean up files
    evidence_path = investigation_jobs[job_id].get("evidence_path")
    if evidence_path and os.path.exists(evidence_path):
        os.remove(evidence_path)
    
    recovered = RECOVERED_DIR / job_id
    if recovered.exists():
        shutil.rmtree(str(recovered))
    
    report = REPORTS_DIR / job_id
    if report.exists():
        shutil.rmtree(str(report))
    
    del investigation_jobs[job_id]
    try:
        case_store.delete_case(job_id)
    except Exception as e:
        print(f"[DB] delete_case({job_id}) failed: {e}")
    return JSONResponse({"message": "Job deleted successfully"})


@app.get("/api/report-file/{job_id}", response_class=HTMLResponse)
async def serve_report_file(job_id: str):
    """
    Serve the HTML report directly via the API.
    This works on BOTH local dev and Vercel (where /tmp files can't be
    served as static files by the CDN).
    """
    if job_id not in investigation_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = investigation_jobs[job_id]
    if job["status"] != "completed":
        raise HTTPException(status_code=400, detail="Report not ready yet")

    report_path = REPORTS_DIR / job_id / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    with open(str(report_path), "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.post("/api/config/openai")
async def set_openai_key(data: dict):
    """Set OpenAI API key at runtime (session-based)."""
    key = data.get("key", "").strip()
    if key:
        os.environ["OPENAI_API_KEY"] = key
        return JSONResponse({"status": "configured"})
    return JSONResponse({"status": "skipped"})


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    # Check tool availability
    tools = {}
    for tool in ["mmls", "fsstat", "fls", "ils", "tsk_recover", "exiftool", "photorec", "foremost"]:
        tools[tool] = shutil.which(tool) is not None
    return JSONResponse({
        "status": "healthy",
        "tools": tools,
        "database": case_store.health(),
        "agent_auth_configured": bool(os.getenv("AGENT_API_KEY", "").strip()),
        "timestamp": datetime.now().isoformat(),
    })


# ─────────────────────────────────────────
# Startup — rehydrate the in-memory cache from MongoDB
# ─────────────────────────────────────────

@app.on_event("startup")
async def _rehydrate_cases_from_db() -> None:
    """
    When the backend restarts, pull every previously stored case from Mongo
    back into the `investigation_jobs` dict so the UI's list view still shows
    historical investigations.
    """
    try:
        cases = case_store.load_all()
        loaded = 0
        for cid, doc in cases.items():
            # Jobs that were "running" when the server died can't resume — mark
            # them as interrupted rather than leaving them stuck at X% forever.
            if doc.get("status") == "running":
                doc["status"] = "interrupted"
                doc["error"] = "Server restarted while analysis was in progress"
                case_store.update_case(cid, {
                    "status": "interrupted",
                    "error": doc["error"],
                })
            investigation_jobs[cid] = doc
            loaded += 1
        print(f"[startup] Rehydrated {loaded} cases from {case_store.health()['backend']}")
    except Exception as e:
        print(f"[startup] Case rehydration failed: {e}")


# ─────────────────────────────────────────
# Spec-compliant endpoint aliases
# ─────────────────────────────────────────
# The requirements document prescribes /analyze, /results/{case_id},
# /timeline/{case_id}, /report/{case_id}. These routes delegate to the existing
# /api/* handlers so both the frontend and a spec-conformant agent work.

def _require_case(case_id: str) -> dict:
    """Resolve a case from memory first, DB second. Raise 404 otherwise."""
    job = investigation_jobs.get(case_id)
    if job is None:
        job = case_store.get_case(case_id)
        if job is not None:
            investigation_jobs[case_id] = job
    if job is None:
        raise HTTPException(status_code=404, detail=f"Case not found: {case_id}")
    return job


@app.post("/analyze")
async def analyze_alias(
    background_tasks: BackgroundTasks,
    evidence: UploadFile = File(...),
    keywords: str = Form(default="password,login,bitcoin,admin,secret,gmail,exe,pdf"),
):
    """Spec alias for POST /api/investigate."""
    return await start_investigation(
        background_tasks=background_tasks,
        evidence=evidence,
        keywords=keywords,
    )


@app.get("/results/{case_id}")
async def results_alias(case_id: str):
    """Spec alias — returns the full structured results JSON for a completed case."""
    job = _require_case(case_id)
    if job.get("status") != "completed":
        return JSONResponse({
            "case_id": case_id,
            "status": job.get("status"),
            "progress": job.get("progress"),
            "message": "Analysis not complete",
        }, status_code=202)
    return JSONResponse({
        "case_id": case_id,
        "evidence_name": job.get("evidence_name"),
        "evidence_type": job.get("evidence_type"),
        "hashes": job.get("hashes", {}),
        "disk_results": job.get("disk_results", {}),
        "artifacts": job.get("artifacts", {}),
        "timeline": job.get("timeline", [])[:200],
        "search_results": job.get("search_results", {}),
        "ai_summary": job.get("ai_summary", ""),
        "recovered_count": job.get("recovered_count", 0),
        "created_at": job.get("created_at"),
        "completed_at": job.get("completed_at"),
    })


@app.get("/timeline/{case_id}")
async def timeline_alias(case_id: str, limit: int = 500):
    """
    Return the forensic timeline for a case in a visualization-ready shape:
    a list of events sorted chronologically with {timestamp, action, file}.
    """
    job = _require_case(case_id)
    raw_tl = job.get("timeline", []) or []

    # Normalise heterogeneous timeline shapes into a single schema so the
    # frontend / a vis library can consume it without special-casing.
    events = []
    for ev in raw_tl[:limit]:
        events.append({
            "timestamp": ev.get("timestamp") or ev.get("time") or ev.get("datetime"),
            "action": ev.get("action") or ev.get("macb") or ev.get("event") or "access",
            "file": ev.get("file") or ev.get("path") or ev.get("name"),
            "size": ev.get("size"),
            "inode": ev.get("inode") or ev.get("meta_addr"),
        })
    return JSONResponse({
        "case_id": case_id,
        "count": len(events),
        "truncated": len(raw_tl) > len(events),
        "events": events,
    })


# ─────────────────────────────────────────
# PDF report — new endpoint
# ─────────────────────────────────────────

def _render_pdf(case_id: str) -> Path:
    """Render (or re-render) the PDF for a case and return its path."""
    job = _require_case(case_id)
    if job.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Analysis not complete")

    pdf_dir = REPORTS_DIR / case_id
    pdf_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = pdf_dir / f"forensic_report_{case_id}.pdf"

    generate_pdf_report(
        case_id=case_id,
        evidence_name=job.get("evidence_name", "unknown"),
        evidence_type=job.get("evidence_type", "unknown"),
        hashes=job.get("hashes", {}),
        disk_results=job.get("disk_results", {}),
        artifacts=job.get("artifacts", {}),
        timeline=job.get("timeline", []),
        search_results=job.get("search_results", {}),
        ai_summary=job.get("ai_summary", ""),
        output_path=str(pdf_path),
        created_at=job.get("completed_at") or job.get("created_at"),
        recovered_count=job.get("recovered_count", 0),
    )
    return pdf_path


@app.get("/api/report/{case_id}/pdf")
async def download_pdf_report(case_id: str):
    """Download the professional PDF forensic report for a completed case."""
    pdf_path = _render_pdf(case_id)
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"forensic_report_{case_id}.pdf",
    )


@app.get("/report/{case_id}")
async def download_pdf_report_alias(case_id: str):
    """Spec alias — /report/{case_id} serves the PDF."""
    return await download_pdf_report(case_id)


# ─────────────────────────────────────────
# Agent endpoint (API-key protected)
# ─────────────────────────────────────────

@app.post("/api/agent/upload")
async def agent_upload(
    background_tasks: BackgroundTasks,
    evidence: UploadFile = File(...),
    keywords: str = Form(default="password,login,bitcoin,admin,secret"),
    investigator: str = Form(default="agent"),
    _auth: None = Depends(require_agent_api_key),
):
    """
    Upload evidence from a remote agent CLI.

    Authentication
    --------------
    Requires a valid ``X-API-Key`` header matching AGENT_API_KEY on the server.
    See backend/modules/auth.py for details.
    """
    job_id = str(uuid.uuid4())[:8]
    safe_name = (evidence.filename or "evidence.bin").replace(" ", "_")
    evidence_path = UPLOAD_DIR / f"{job_id}_{safe_name}"

    async with aiofiles.open(str(evidence_path), "wb") as f:
        content = await evidence.read()
        await f.write(content)

    kw_list = [k.strip() for k in keywords.split(",") if k.strip()]

    investigation_jobs[job_id] = {
        "job_id": job_id,
        "case_id": job_id,
        "evidence_name": evidence.filename,
        "evidence_path": str(evidence_path),
        "status": "queued",
        "progress": 0,
        "created_at": datetime.now().isoformat(),
        "log": [],
        "keywords": kw_list,
        "source": "agent",
        "investigator": investigator,
    }
    _persist_job(job_id)

    background_tasks.add_task(
        run_full_analysis, job_id, evidence_path, evidence.filename, kw_list
    )

    return JSONResponse({
        "case_id": job_id,
        "job_id": job_id,
        "status": "queued",
        "status_url": f"/api/status/{job_id}",
        "results_url": f"/results/{job_id}",
        "pdf_url": f"/report/{job_id}",
        "message": "Evidence received. Analysis started.",
    })


# ─────────────────────────────────────────
# Agent findings endpoint
# ─────────────────────────────────────────
# Accepts a JSON "findings" package produced by the local agent scanner and
# materialises it as a full case — so the UI, /results, /timeline, /report all
# work without the raw evidence ever being uploaded.
#
# This is how the "download agent → scan locally → view report online"
# workflow hangs together. Authentication is required (X-API-Key).


def _findings_to_case(findings: dict, case_id: str) -> dict:
    """
    Translate a scanner-produced findings dict into the shape the rest of the
    backend expects from run_full_analysis (artifacts / timeline / search /
    disk_results / hashes). This is the bridge between "remote scan" and
    "normal case" so the existing PDF/JSON/HTML report machinery works.
    """
    files = findings.get("files") or []
    summary = findings.get("summary") or {}
    host = findings.get("host") or {}
    now_iso = datetime.utcnow().isoformat()

    # ── Buckets (same shape ArtifactExtractor produces) ─────────────────────
    multimedia: list = []
    documents: list = []
    metadata_entries: list = []
    browser_history: list = []  # not inferable from a logical scan
    timeline_events: list = []
    deleted_files: list = []    # only available when we get a disk image

    for f in files:
        ftype = f.get("type")
        entry = {
            "path": f.get("path"),
            "name": f.get("name"),
            "size": f.get("size"),
            "md5": f.get("md5"),
            "sha256": f.get("sha256"),
            "mtime": f.get("mtime"),
            "atime": f.get("atime"),
            "ctime": f.get("ctime"),
        }

        if ftype == "image":
            entry["type"] = "image"
            entry["exif"] = f.get("exif") or {}
            multimedia.append(entry)
            if entry["exif"]:
                metadata_entries.append({
                    "file": f.get("name"),
                    "metadata": entry["exif"],
                })
        elif ftype in {"pdf", "docx", "text"}:
            entry["type"] = ftype
            entry["text_preview"] = f.get("text_preview", "")
            entry["metadata"] = f.get("metadata", {})
            documents.append(entry)
            if entry["metadata"]:
                metadata_entries.append({
                    "file": f.get("name"),
                    "metadata": entry["metadata"],
                })
        elif ftype in {"archive_zip", "archive_rar"}:
            entry["type"] = ftype
            entry["member_count"] = f.get("member_count", 0)
            entry["members_preview"] = (f.get("members") or [])[:10]
            documents.append(entry)

        # ── Timeline: one event per MAC time, if present ────────────────────
        for macb, ts in (
            ("modified", f.get("mtime")),
            ("accessed", f.get("atime")),
            ("changed",  f.get("ctime")),
        ):
            if ts:
                timeline_events.append({
                    "timestamp": ts,
                    "action": macb,
                    "file": f.get("path"),
                    "size": f.get("size"),
                })

    timeline_events.sort(key=lambda e: e["timestamp"] or "")

    # ── Keyword search across text previews ────────────────────────────────
    search_results: dict = {}
    for kw in (findings.get("keywords") or []):
        hits = []
        kw_l = kw.lower()
        for f in files:
            haystack = " ".join(filter(None, [
                f.get("text_preview", ""),
                f.get("name", ""),
            ])).lower()
            if kw_l and kw_l in haystack:
                hits.append({
                    "file": f.get("path"),
                    "match": f.get("name"),
                    "context": (f.get("text_preview", "") or "")[:200],
                })
        if hits:
            search_results[kw] = hits

    # ── Chain-of-custody hash for the "root" — a hash of hashes ────────────
    all_sha = [f.get("sha256") for f in files if f.get("sha256")]
    import hashlib as _hashlib
    roll = _hashlib.sha256("\n".join(all_sha).encode()).hexdigest() if all_sha else ""

    return {
        "job_id": case_id,
        "case_id": case_id,
        "evidence_name": os.path.basename(findings.get("root") or "logical_scan"),
        "evidence_type": "logical_scan",
        "status": "completed",
        "progress": 100,
        "source": "agent-scan",
        "investigator": findings.get("investigator", "agent"),
        "created_at": now_iso,
        "completed_at": now_iso,
        "scanned_at": findings.get("scanned_at"),
        "host": host,
        "root": findings.get("root"),
        "keywords": findings.get("keywords", []),
        "hashes": {
            "sha256_of_contents": roll,
            "file_count": len(files),
        },
        "disk_results": {
            "partitions": [],
            "deleted_files": deleted_files,
            "file_system": "logical",
        },
        "artifacts": {
            "multimedia": multimedia,
            "documents": documents,
            "metadata": metadata_entries,
            "browser_history": browser_history,
        },
        "timeline": timeline_events,
        "search_results": search_results,
        "recovered_count": len(files),
        "ai_summary": _local_summary_from_findings(findings, len(files), timeline_events, search_results),
        "log": [f"[{datetime.now().strftime('%H:%M:%S')}] Remote scan ingested from agent"],
        "scanner_findings_sample": {
            "summary": summary,
            "errors": (findings.get("errors") or [])[:20],
            "rar_files": findings.get("rar_files", []),
            "images_to_upload": findings.get("images_to_upload", []),
        },
    }


def _local_summary_from_findings(findings: dict, n_files: int, timeline: list, search: dict) -> str:
    """Tiny markdown summary used when OpenAI isn't configured for agent scans."""
    summary = findings.get("summary", {})
    by_type = summary.get("by_type", {})
    host = findings.get("host", {})
    flagged = [f"**{k}** ({len(v)} hits)" for k, v in search.items() if v]
    return f"""## Remote Agent Scan — {findings.get('root', 'unknown')}

**Host:** {host.get('hostname', '?')} ({host.get('os', '?')}, user `{host.get('user', '?')}`)
**Scanned at:** {findings.get('scanned_at', '?')}
**Scanner version:** {findings.get('scanner_version', '?')}

### Summary
- **{n_files}** files examined locally
- **{summary.get('total_size_bytes', 0):,}** bytes total
- File types: {', '.join(f'{k}={v}' for k, v in by_type.items()) or '—'}
- **{summary.get('with_exif', 0)}** files carry EXIF metadata
- **{summary.get('with_text', 0)}** files had extractable text
- **{len(timeline)}** timeline events (MAC times)

### Keyword findings
{('- ' + '; '.join(flagged)) if flagged else '- No keyword hits.'}

### Next steps
Review the file listing, timeline and keyword hits below. Disk images found
during the scan were **not** analysed locally — re-run with
`forensic-agent upload <disk.img>` to send them to the backend for Sleuth Kit.
"""


@app.post("/api/agent/findings")
async def agent_findings(
    request: Request,
    _auth: None = Depends(require_agent_api_key),
):
    """
    Ingest a findings package from the local agent scanner.

    The body must be JSON produced by ``scanner.scan()``. The backend creates
    a new case and the normal /results, /timeline and /report endpoints then
    serve it — no raw evidence is ever shipped over the wire.
    """
    try:
        findings = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")

    if not isinstance(findings, dict) or "files" not in findings:
        raise HTTPException(
            status_code=422,
            detail="Body must be a findings dict with a 'files' list.",
        )

    case_id = str(uuid.uuid4())[:8]
    case = _findings_to_case(findings, case_id)
    investigation_jobs[case_id] = case
    _persist_job(case_id)

    return JSONResponse({
        "case_id": case_id,
        "job_id": case_id,
        "status": "completed",
        "status_url": f"/api/status/{case_id}",
        "results_url": f"/results/{case_id}",
        "timeline_url": f"/timeline/{case_id}",
        "pdf_url": f"/report/{case_id}",
        "file_count": case["recovered_count"],
        "images_to_upload": findings.get("images_to_upload", []),
        "message": "Findings ingested and case created.",
    })


# ─────────────────────────────────────────
# Agent downloads — serve binaries / source from /downloads
# ─────────────────────────────────────────

@app.get("/download-agent")
async def download_agent_page(request: Request):
    """Render the Download Agent page with install instructions for Mac + Windows."""
    return templates.TemplateResponse(request, "download_agent.html")


@app.get("/api/agent/download/{platform_name}")
async def download_agent_binary(platform_name: str):
    """
    Serve a pre-built agent binary for the requested platform.

    ``platform_name`` must be one of: ``macos``, ``windows``, ``source``.
    Binaries are built with PyInstaller (see agent/build_*.sh) and placed in
    ``backend/static/downloads/`` before deployment.
    """
    mapping = {
        "macos":   ("forensic-agent-macos",   "application/octet-stream"),
        "windows": ("forensic-agent-windows.exe", "application/octet-stream"),
        "source":  ("forensic-agent-source.zip", "application/zip"),
    }
    if platform_name not in mapping:
        raise HTTPException(status_code=404, detail="Unknown platform")
    fname, mime = mapping[platform_name]
    fpath = STATIC_DIR / "downloads" / fname
    if not fpath.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"{fname} not built yet. Run agent/build_{platform_name}.sh "
                "(or build_windows.bat) on the matching OS and place the binary "
                "in backend/static/downloads/."
            ),
        )
    return FileResponse(path=str(fpath), media_type=mime, filename=fname)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
