"""
scanner.py — Local forensic scanner used by the agent.

Runs on the investigator's machine and produces a JSON "findings" package
that the agent then POSTs to the backend's /api/agent/findings endpoint.
No raw evidence leaves the local machine for anything except disk images,
which must go to the backend for Sleuth Kit processing.

Per-type handling
-----------------
Image  (.jpg .jpeg .bmp .png .gif .tif .tiff)      → hash + EXIF via exiftool
PDF   (.pdf)                                       → hash + text extraction
Word  (.docx)                                      → hash + text extraction
Text  (.txt .csv .log .md .json .xml .html .htm)   → hash + first-512-byte preview
Archive (.zip)                                     → extract + recurse
Archive (.rar)                                     → prompt user (install unrar, or skip)
Disk image (.dd .img .raw .iso .001 .vmdk .e01)    → flagged for backend upload
Everything else                                    → hash + basic metadata only

Output shape
------------
{
    "scanner_version": "1.0.0",
    "host":      {"os": "darwin-23.0", "user": "admin", "hostname": "MacBook-Pro"},
    "root":      "/Users/admin/Documents",
    "scanned_at": "2026-04-18T20:15:00Z",
    "files":     [{...}],      # one entry per file (recursive)
    "images_to_upload": [...], # absolute paths of disk images that need TSK
    "errors":    [...],
    "summary":   {
        "total_files": N,
        "total_size_bytes": N,
        "by_type": {"image": N, "pdf": N, ...},
        "with_exif": N,
        "with_text": N,
    },
}
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Type tables — extension-driven classification.
# ─────────────────────────────────────────────────────────────────────────────

EXT_IMAGE     = {".jpg", ".jpeg", ".bmp", ".png", ".gif", ".tif", ".tiff"}
EXT_PDF       = {".pdf"}
EXT_DOCX      = {".docx"}
EXT_TEXT      = {".txt", ".csv", ".log", ".md", ".json", ".xml", ".html", ".htm", ".yaml", ".yml", ".ini"}
EXT_ZIP       = {".zip"}
EXT_RAR       = {".rar"}
EXT_DISK_IMG  = {".dd", ".img", ".raw", ".iso", ".001", ".vmdk", ".e01", ".aff", ".ewf", ".vhd"}

# Hard cap so a scan of a huge folder doesn't eat all memory. The backend's
# report can say "truncated at N files" without losing analytic value.
MAX_FILES = 10_000
# Per-file text preview size — enough to support keyword search, small enough
# not to balloon the findings JSON.
TEXT_PREVIEW_BYTES = 2048
TEXT_PREVIEW_CHARS = 1500
CHUNK_SIZE = 1024 * 1024  # 1 MiB for hashing

# Callback signature: (rar_path, num_rar_files) -> bool "include?"
RarDecisionFn = Callable[[Path, int], bool]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stat_times(path: Path) -> Dict[str, Optional[str]]:
    """File MAC times in ISO format. Missing atime/ctime → None."""
    try:
        st = path.stat()
    except OSError:
        return {"mtime": None, "atime": None, "ctime": None}
    def _iso(ts: float) -> Optional[str]:
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return None
    return {
        "mtime": _iso(st.st_mtime),
        "atime": _iso(st.st_atime),
        "ctime": _iso(st.st_ctime),
    }


def _hash_file(path: Path) -> Dict[str, Any]:
    """MD5 + SHA-256 + size. Streams to avoid memory issues on multi-GB files."""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                md5.update(chunk)
                sha.update(chunk)
                size += len(chunk)
    except OSError as e:
        return {"error": f"hash failed: {e}"}
    return {
        "md5": md5.hexdigest(),
        "sha256": sha.hexdigest(),
        "size": size,
    }


def _classify(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in EXT_IMAGE:    return "image"
    if ext in EXT_PDF:      return "pdf"
    if ext in EXT_DOCX:     return "docx"
    if ext in EXT_TEXT:     return "text"
    if ext in EXT_ZIP:      return "archive_zip"
    if ext in EXT_RAR:      return "archive_rar"
    if ext in EXT_DISK_IMG: return "disk_image"
    return "other"


# ─────────────────────────────────────────────────────────────────────────────
# Per-type extractors — all are best-effort and never raise.
# ─────────────────────────────────────────────────────────────────────────────


def _extract_exif(path: Path) -> Dict[str, Any]:
    """Shell out to exiftool if available; otherwise return {}."""
    from shutil import which
    if not which("exiftool"):
        return {}
    try:
        out = subprocess.run(
            ["exiftool", "-json", "-fast", "-n", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0 and out.stdout.strip():
            data = json.loads(out.stdout)
            if isinstance(data, list) and data:
                # Filter out non-forensic metadata (tool versions, etc.)
                meta = data[0]
                keep_keys = {
                    "FileType", "MIMEType", "ImageWidth", "ImageHeight",
                    "Make", "Model", "LensModel", "Software",
                    "DateTimeOriginal", "CreateDate", "ModifyDate",
                    "GPSLatitude", "GPSLongitude", "GPSAltitude",
                    "Artist", "Copyright", "SerialNumber",
                    "ExposureTime", "FNumber", "ISO", "FocalLength",
                }
                return {k: meta.get(k) for k in keep_keys if meta.get(k) is not None}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return {}


def _extract_pdf_text(path: Path) -> Dict[str, Any]:
    """Extract the first N pages' text. Returns {text_preview, page_count}."""
    try:
        from pypdf import PdfReader  # type: ignore
    except ImportError:
        return {}
    try:
        reader = PdfReader(str(path), strict=False)
        preview = []
        for page in reader.pages[:3]:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            preview.append(t)
            if sum(len(p) for p in preview) > TEXT_PREVIEW_CHARS:
                break
        txt = "\n".join(preview)[:TEXT_PREVIEW_CHARS]
        return {
            "page_count": len(reader.pages),
            "text_preview": txt.strip(),
            "metadata": {k: str(v) for k, v in (reader.metadata or {}).items()} if reader.metadata else {},
        }
    except Exception as e:
        return {"error": f"pdf parse failed: {e}"}


def _extract_docx_text(path: Path) -> Dict[str, Any]:
    try:
        from docx import Document  # type: ignore (python-docx)
    except ImportError:
        return {}
    try:
        doc = Document(str(path))
        paras = [p.text for p in doc.paragraphs if p.text]
        txt = "\n".join(paras)[:TEXT_PREVIEW_CHARS]
        core = doc.core_properties
        return {
            "paragraph_count": len(paras),
            "text_preview": txt,
            "metadata": {
                "author": core.author or None,
                "title": core.title or None,
                "created": str(core.created) if core.created else None,
                "modified": str(core.modified) if core.modified else None,
                "last_modified_by": core.last_modified_by or None,
            },
        }
    except Exception as e:
        return {"error": f"docx parse failed: {e}"}


def _extract_text_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("rb") as f:
            raw = f.read(TEXT_PREVIEW_BYTES)
        # Try UTF-8 first, fall back to latin-1 (always decodes, never raises).
        try:
            txt = raw.decode("utf-8")
        except UnicodeDecodeError:
            txt = raw.decode("latin-1", errors="replace")
        return {"text_preview": txt[:TEXT_PREVIEW_CHARS]}
    except OSError as e:
        return {"error": f"text read failed: {e}"}


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────


def scan(
    root: Path,
    *,
    rar_decision: Optional[RarDecisionFn] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, Any]:
    """
    Walk `root` (file or directory), produce a findings dict.

    rar_decision
        Callback invoked if any `.rar` files are encountered. Signature:
            rar_decision(sample_rar_path, num_rar_files) -> bool
        Return True to attempt inclusion (requires unrar), False to skip.
        Default (None): skip.
    on_progress
        Optional callable (done, total) invoked after each file so the CLI can
        render a progress bar.
    """
    root = root.resolve()
    findings: Dict[str, Any] = {
        "scanner_version": "1.0.0",
        "host": {
            "os":       f"{platform.system().lower()}-{platform.release()}",
            "user":     getpass.getuser(),
            "hostname": socket.gethostname(),
            "python":   platform.python_version(),
        },
        "root": str(root),
        "scanned_at": _now_iso(),
        "files": [],
        "images_to_upload": [],
        "rar_files": [],
        "errors": [],
        "summary": {
            "total_files": 0, "total_size_bytes": 0,
            "by_type": {}, "with_exif": 0, "with_text": 0,
            "truncated": False,
        },
    }
    by_type: Dict[str, int] = {}

    # ── Collect file list up front so we know the total for progress bars ──
    all_paths: List[Path] = []
    if root.is_file():
        all_paths = [root]
    else:
        for p in root.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    all_paths.append(p)
            except OSError:
                continue
            if len(all_paths) >= MAX_FILES:
                findings["summary"]["truncated"] = True
                break

    # ── Handle RAR decision once, up front ──────────────────────────────────
    rar_paths = [p for p in all_paths if p.suffix.lower() in EXT_RAR]
    include_rar = False
    if rar_paths and rar_decision is not None:
        include_rar = bool(rar_decision(rar_paths[0], len(rar_paths)))

    # ── Walk ────────────────────────────────────────────────────────────────
    total = len(all_paths)
    for i, path in enumerate(all_paths, 1):
        try:
            entry = _process_file(path, include_rar=include_rar, root=root)
            if entry is None:
                continue
            findings["files"].append(entry)
            by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
            findings["summary"]["total_size_bytes"] += entry.get("size") or 0
            if entry.get("exif"):         findings["summary"]["with_exif"] += 1
            if entry.get("text_preview"): findings["summary"]["with_text"] += 1
            if entry["type"] == "disk_image":
                findings["images_to_upload"].append(entry["path"])
            if entry["type"] == "archive_rar":
                findings["rar_files"].append(entry["path"])
        except Exception as e:
            findings["errors"].append({"path": str(path), "error": str(e)})
        if on_progress:
            on_progress(i, total)

    findings["summary"]["total_files"] = len(findings["files"])
    findings["summary"]["by_type"] = by_type
    return findings


def _process_file(path: Path, *, include_rar: bool, root: Path) -> Optional[Dict[str, Any]]:
    """
    Produce a per-file entry. For archive_zip, also recurses into contents
    (up to MAX_FILES globally — caller checks).
    """
    ftype = _classify(path)
    times = _stat_times(path)
    hashes = _hash_file(path)

    entry: Dict[str, Any] = {
        "path": str(path),
        "relative_path": str(path.relative_to(root)) if root in path.parents or path == root else path.name,
        "name": path.name,
        "extension": path.suffix.lower(),
        "type": ftype,
        **times,
        **hashes,
    }

    # Disk images: no local deep processing — flag for upload.
    if ftype == "disk_image":
        entry["note"] = "Disk image — Sleuth Kit must run server-side. Upload required."
        return entry

    # Type-specific extraction.
    if ftype == "image":
        exif = _extract_exif(path)
        if exif:
            entry["exif"] = exif
    elif ftype == "pdf":
        entry.update(_extract_pdf_text(path))
    elif ftype == "docx":
        entry.update(_extract_docx_text(path))
    elif ftype == "text":
        entry.update(_extract_text_file(path))
    elif ftype == "archive_zip":
        entry["contents"] = _scan_zip(path)
    elif ftype == "archive_rar":
        if include_rar:
            rar_info = _scan_rar(path)
            entry.update(rar_info)
        else:
            entry["note"] = "RAR contents skipped by user choice."

    return entry


def _scan_zip(path: Path) -> Dict[str, Any]:
    """
    List the members of a zip without extracting. For each member, record
    name, size, compressed size and CRC. We deliberately don't recurse full
    analysis inside zips here to keep memory bounded.
    """
    try:
        with zipfile.ZipFile(path, "r") as zf:
            members = []
            for info in zf.infolist():
                members.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "crc32": f"{info.CRC:08x}",
                    "modified": f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d}T"
                                f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}",
                })
            return {
                "member_count": len(members),
                "members": members[:500],  # cap
                "truncated": len(members) > 500,
            }
    except (zipfile.BadZipFile, OSError) as e:
        return {"error": f"zip parse failed: {e}"}


def _scan_rar(path: Path) -> Dict[str, Any]:
    """
    Parse a RAR archive if `rarfile` and `unrar` are both available. Otherwise
    return an informative note. Never raises.
    """
    try:
        import rarfile  # type: ignore
    except ImportError:
        return {"error": "rarfile Python package not installed — run: pip install rarfile"}
    from shutil import which
    if not which("unrar") and not which("unar"):
        return {"error": "`unrar` binary not found on PATH. Install via `brew install rar` or equivalent."}
    try:
        with rarfile.RarFile(str(path)) as rf:
            members = [
                {"name": m.filename, "size": m.file_size, "modified": str(m.mtime)}
                for m in rf.infolist()
            ]
            return {"member_count": len(members), "members": members[:500]}
    except Exception as e:
        return {"error": f"rar parse failed: {e}"}
