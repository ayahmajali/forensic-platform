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

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Form
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

# In-memory job store (production: use Redis/DB)
investigation_jobs: dict = {}


# ─────────────────────────────────────────
# Background Analysis Task
# ─────────────────────────────────────────
async def run_full_analysis(job_id: str, evidence_path: Path, evidence_name: str, keywords: list):
    """Full forensic analysis pipeline running in the background."""
    job = investigation_jobs[job_id]
    job["status"] = "running"
    job["progress"] = 5
    job["log"] = []

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

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        job["status"] = "failed"
        job["error"] = str(e)
        job["traceback"] = tb
        log(f"❌ Analysis failed: {e}")
        print(tb)


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
    return templates.TemplateResponse("index.html", {"request": request})


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
        "evidence_name": evidence.filename,
        "evidence_path": str(evidence_path),
        "status": "queued",
        "progress": 0,
        "created_at": datetime.now().isoformat(),
        "log": [],
        "keywords": kw_list
    }
    
    background_tasks.add_task(
        run_full_analysis, job_id, evidence_path, evidence.filename, kw_list
    )
    
    return JSONResponse({"job_id": job_id, "status": "queued", "message": "Investigation started"})


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
    return JSONResponse({"status": "healthy", "tools": tools, "timestamp": datetime.now().isoformat()})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
