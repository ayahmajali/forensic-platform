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
EXT_VIDEO     = {".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm", ".m4v"}
EXT_AUDIO     = {".mp3", ".wav", ".m4a", ".ogg", ".flac", ".aac"}
EXT_SQLITE    = {".sqlite", ".sqlite3", ".db"}

# Filenames that indicate a browser profile database. SQLite magic bytes are
# confirmed before parsing — otherwise a file named "History" but not actually
# SQLite would blow up sqlite3.connect.
BROWSER_DB_NAMES = {
    "History",         # Chrome / Chromium / Edge / Brave / Opera / Vivaldi / Arc / Yandex
    "history",         # case variations
    "History.db",      # Safari (macOS)
    "places.sqlite",   # Firefox / Tor Browser / Waterfox / LibreWolf
    "Cookies",         # Chrome cookies (useful forensic artefact)
    "Login Data",      # Chrome saved logins
}

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
    """
    MD5 + SHA-1 + SHA-256 + size.

    All three digests are computed in a single streaming pass — cost of the
    extra SHA-1 is ~5% on top of the two other hashes, which is a fair trade
    for chain-of-custody reports that require all three (Autopsy and most
    court-admissible forensic tools compute the same triple).
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
    except OSError as e:
        return {"error": f"hash failed: {e}"}
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
    }


def _classify(path: Path) -> str:
    name = path.name
    ext = path.suffix.lower()

    # Browser profile databases are detected by filename, not extension —
    # Chrome's 'History' file has no extension at all.
    if name in BROWSER_DB_NAMES: return "browser_db"

    if ext in EXT_IMAGE:    return "image"
    if ext in EXT_PDF:      return "pdf"
    if ext in EXT_DOCX:     return "docx"
    if ext in EXT_TEXT:     return "text"
    if ext in EXT_ZIP:      return "archive_zip"
    if ext in EXT_RAR:      return "archive_rar"
    if ext in EXT_DISK_IMG: return "disk_image"
    if ext in EXT_VIDEO:    return "video"
    if ext in EXT_AUDIO:    return "audio"
    if ext in EXT_SQLITE:   return "sqlite"
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
# Browser history parser — Chrome / Edge / Firefox
# ─────────────────────────────────────────────────────────────────────────────

# How many visit rows we pull from each database. 500 is plenty for a report
# and keeps the findings JSON small enough to POST in a single request.
BROWSER_HISTORY_ROW_CAP = 500

# Chrome stores timestamps as microseconds since 1601-01-01 UTC.
# Subtracting this offset converts to standard Unix epoch microseconds.
CHROME_EPOCH_OFFSET_US = 11_644_473_600_000_000


def _is_sqlite(path: Path) -> bool:
    """Check SQLite magic bytes before opening with sqlite3 — avoids noisy
    exceptions when a file named `History` turns out to be something else."""
    try:
        with path.open("rb") as f:
            return f.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def _chrome_time_to_iso(webkit_us: Optional[int]) -> Optional[str]:
    if not webkit_us:
        return None
    try:
        unix_us = webkit_us - CHROME_EPOCH_OFFSET_US
        if unix_us <= 0:
            return None
        return datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _firefox_time_to_iso(epoch_us: Optional[int]) -> Optional[str]:
    if not epoch_us:
        return None
    try:
        return datetime.fromtimestamp(epoch_us / 1_000_000, tz=timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _copy_to_tmp(path: Path) -> Optional[Path]:
    """
    Browsers lock their SQLite DB while running. Copying to a temp file avoids
    `database is locked` errors at the cost of one read. Returns the temp path
    (caller responsible for cleanup) or None on failure.
    """
    import shutil
    import tempfile
    try:
        fd, tmp = tempfile.mkstemp(prefix="fa_browser_", suffix=".sqlite")
        os.close(fd)
        shutil.copyfile(str(path), tmp)
        return Path(tmp)
    except OSError:
        return None


def _parse_chrome_history(path: Path) -> List[Dict[str, Any]]:
    """
    Read the `urls` + `visits` tables from a Chrome/Edge/Chromium History DB.
    Returns a list of {url, title, visit_count, last_visit_at, browser}.
    """
    import sqlite3

    tmp = _copy_to_tmp(path)
    target = tmp or path
    out: List[Dict[str, Any]] = []
    try:
        con = sqlite3.connect(f"file:{target}?mode=ro&immutable=1", uri=True, timeout=2)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(
            "SELECT url, title, visit_count, last_visit_time "
            "FROM urls ORDER BY last_visit_time DESC LIMIT ?",
            (BROWSER_HISTORY_ROW_CAP,),
        )
        for row in cur.fetchall():
            out.append({
                "url": row["url"],
                "title": row["title"] or "",
                "visit_count": row["visit_count"] or 0,
                "last_visit_at": _chrome_time_to_iso(row["last_visit_time"]),
                "browser": "chrome/edge",
                "source": str(path),
            })
        con.close()
    except sqlite3.DatabaseError as e:
        return [{"error": f"chrome history read failed: {e}", "source": str(path)}]
    finally:
        if tmp and tmp.exists():
            try: tmp.unlink()
            except OSError: pass
    return out


def _parse_firefox_history(path: Path) -> List[Dict[str, Any]]:
    """
    Read moz_places from a Firefox profile's places.sqlite. Returns entries
    in the same shape as _parse_chrome_history so downstream code is uniform.
    """
    import sqlite3

    tmp = _copy_to_tmp(path)
    target = tmp or path
    out: List[Dict[str, Any]] = []
    try:
        con = sqlite3.connect(f"file:{target}?mode=ro&immutable=1", uri=True, timeout=2)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(
            "SELECT url, title, visit_count, last_visit_date "
            "FROM moz_places ORDER BY last_visit_date DESC LIMIT ?",
            (BROWSER_HISTORY_ROW_CAP,),
        )
        for row in cur.fetchall():
            out.append({
                "url": row["url"],
                "title": row["title"] or "",
                "visit_count": row["visit_count"] or 0,
                "last_visit_at": _firefox_time_to_iso(row["last_visit_date"]),
                "browser": "firefox",
                "source": str(path),
            })
        con.close()
    except sqlite3.DatabaseError as e:
        return [{"error": f"firefox history read failed: {e}", "source": str(path)}]
    finally:
        if tmp and tmp.exists():
            try: tmp.unlink()
            except OSError: pass
    return out


def _extract_browser_history(path: Path) -> Dict[str, Any]:
    """
    Dispatch on filename + SQLite magic. Returns a dict with either a
    `history_entries` list (on success) or `note` (when we can't parse).
    """
    name = path.name
    if name.lower() == "places.sqlite":
        if _is_sqlite(path):
            entries = _parse_firefox_history(path)
            return {"browser": "firefox", "history_entries": entries}
        return {"note": "File named places.sqlite but not a SQLite database."}
    if name in ("History", "history"):
        if _is_sqlite(path):
            entries = _parse_chrome_history(path)
            # Best-effort guess at which Chromium-family browser this is
            # based on the profile path.
            parent = str(path.parent).lower()
            browser = ("edge"   if "edge"    in parent else
                       "brave"  if "brave"   in parent else
                       "opera"  if "opera"   in parent else
                       "chrome")
            return {"browser": browser, "history_entries": entries}
        return {"note": "File named History but not a SQLite database."}
    if name == "History.db":
        if _is_sqlite(path):
            entries = _parse_safari_history(path)
            return {"browser": "safari", "history_entries": entries}
        return {"note": "File named History.db but not a SQLite database."}
    # Cookies / Login Data — flagged but we don't parse them into the report
    # (cookie contents can contain secrets the user didn't consent to exfiltrate).
    return {"note": f"Browser profile DB ({name}) — not parsed (privacy)."}


# ─────────────────────────────────────────────────────────────────────────────
# Safari history — Cocoa epoch (seconds since 2001-01-01 UTC)
# ─────────────────────────────────────────────────────────────────────────────

# Offset between Cocoa reference date (2001-01-01) and Unix epoch (1970-01-01),
# in seconds. Safari stores history_visits.visit_time as a Cocoa timestamp.
COCOA_EPOCH_OFFSET_S = 978_307_200


def _cocoa_time_to_iso(cocoa_s: Optional[float]) -> Optional[str]:
    if not cocoa_s:
        return None
    try:
        unix_s = float(cocoa_s) + COCOA_EPOCH_OFFSET_S
        if unix_s <= 0:
            return None
        return datetime.fromtimestamp(unix_s, tz=timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _parse_safari_history(path: Path) -> List[Dict[str, Any]]:
    """
    Read Safari's History.db (macOS). Joins history_items → history_visits to
    get url, title, visit_count, last_visit_at — same shape as the Chrome/FF
    parsers so the downstream code is uniform.
    """
    import sqlite3

    tmp = _copy_to_tmp(path)
    target = tmp or path
    out: List[Dict[str, Any]] = []
    try:
        con = sqlite3.connect(f"file:{target}?mode=ro&immutable=1", uri=True, timeout=2)
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute(
            """
            SELECT  hi.url              AS url,
                    hv.title            AS title,
                    hi.visit_count      AS visit_count,
                    MAX(hv.visit_time)  AS last_visit_time
            FROM    history_items hi
            JOIN    history_visits hv ON hv.history_item = hi.id
            GROUP BY hi.id
            ORDER BY last_visit_time DESC
            LIMIT  ?
            """,
            (BROWSER_HISTORY_ROW_CAP,),
        )
        for row in cur.fetchall():
            out.append({
                "url": row["url"],
                "title": row["title"] or "",
                "visit_count": row["visit_count"] or 0,
                "last_visit_at": _cocoa_time_to_iso(row["last_visit_time"]),
                "browser": "safari",
                "source": str(path),
            })
        con.close()
    except sqlite3.DatabaseError as e:
        return [{"error": f"safari history read failed: {e}", "source": str(path)}]
    finally:
        if tmp and tmp.exists():
            try: tmp.unlink()
            except OSError: pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# System-wide browser-history discovery
# ─────────────────────────────────────────────────────────────────────────────
# The walk-based extractor above only catches browser DBs that happen to live
# inside the scanned directory. Investigators expect "all browsers on this
# machine" — so we do a dedicated discovery pass over the well-known user-data
# locations per OS. Every supported browser is listed below; each entry carries
# the roots to search plus the glob used to enumerate profiles.
#
# Supported families:
#   • Chromium (History SQLite)   — Chrome, Chromium, Chrome Beta/Canary/Dev,
#     Edge (+ Beta/Dev/Canary), Brave (+ Beta/Nightly), Opera (+ GX/Developer),
#     Vivaldi, Arc, Yandex.
#   • Gecko / Firefox (places.sqlite) — Firefox, Firefox Dev/Nightly/ESR,
#     Waterfox, LibreWolf, Tor Browser.
#   • Apple WebKit (History.db) — Safari (macOS only).


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _browser_registry() -> List[Dict[str, Any]]:
    """
    Return a list of browser descriptors for the current OS.

    Each descriptor:
      {
        "name":          display name,
        "family":        "chromium" | "firefox" | "safari",
        "user_data_dirs":[Path, ...],     # roots to scan
        "profile_glob":  "*" or None,     # None means DB is directly in root
        "db_filename":   "History" | "places.sqlite" | "History.db",
      }
    """
    home = _home()
    system = platform.system().lower()  # "darwin" | "linux" | "windows"

    entries: List[Dict[str, Any]] = []

    # ── macOS ──────────────────────────────────────────────────────────────
    if system == "darwin":
        app_support = home / "Library" / "Application Support"
        chromium_roots = {
            "Google Chrome":        [app_support / "Google" / "Chrome"],
            "Google Chrome Beta":   [app_support / "Google" / "Chrome Beta"],
            "Google Chrome Canary": [app_support / "Google" / "Chrome Canary"],
            "Chromium":             [app_support / "Chromium"],
            "Microsoft Edge":       [app_support / "Microsoft Edge"],
            "Microsoft Edge Beta":  [app_support / "Microsoft Edge Beta"],
            "Microsoft Edge Dev":   [app_support / "Microsoft Edge Dev"],
            "Brave":                [app_support / "BraveSoftware" / "Brave-Browser"],
            "Brave Beta":           [app_support / "BraveSoftware" / "Brave-Browser-Beta"],
            "Brave Nightly":        [app_support / "BraveSoftware" / "Brave-Browser-Nightly"],
            "Vivaldi":              [app_support / "Vivaldi"],
            "Opera":                [app_support / "com.operasoftware.Opera"],
            "Opera GX":             [app_support / "com.operasoftware.OperaGX"],
            "Arc":                  [app_support / "Arc" / "User Data"],
            "Yandex":               [app_support / "Yandex" / "YandexBrowser"],
        }
        for name, roots in chromium_roots.items():
            entries.append({
                "name": name, "family": "chromium",
                "user_data_dirs": roots, "profile_glob": "*",
                "db_filename": "History",
            })
        # Firefox family
        firefox_roots = {
            "Firefox":             [home / "Library" / "Application Support" / "Firefox" / "Profiles"],
            "Firefox Developer":   [home / "Library" / "Application Support" / "Firefox Developer Edition" / "Profiles"],
            "Firefox Nightly":     [home / "Library" / "Application Support" / "Firefox Nightly" / "Profiles"],
            "Waterfox":            [home / "Library" / "Application Support" / "Waterfox" / "Profiles"],
            "LibreWolf":           [home / "Library" / "Application Support" / "LibreWolf" / "Profiles"],
            "Tor Browser":         [home / "Library" / "Application Support" / "TorBrowser-Data" / "Browser"],
        }
        for name, roots in firefox_roots.items():
            entries.append({
                "name": name, "family": "firefox",
                "user_data_dirs": roots, "profile_glob": "*",
                "db_filename": "places.sqlite",
            })
        # Safari — single DB, no profile subdir.
        entries.append({
            "name": "Safari", "family": "safari",
            "user_data_dirs": [home / "Library" / "Safari"],
            "profile_glob": None, "db_filename": "History.db",
        })

    # ── Linux ──────────────────────────────────────────────────────────────
    elif system == "linux":
        cfg = home / ".config"
        chromium_roots = {
            "Google Chrome":       [cfg / "google-chrome"],
            "Google Chrome Beta":  [cfg / "google-chrome-beta"],
            "Google Chrome Unstable": [cfg / "google-chrome-unstable"],
            "Chromium":            [cfg / "chromium", home / "snap" / "chromium" / "common" / "chromium"],
            "Microsoft Edge":      [cfg / "microsoft-edge"],
            "Microsoft Edge Beta": [cfg / "microsoft-edge-beta"],
            "Microsoft Edge Dev":  [cfg / "microsoft-edge-dev"],
            "Brave":               [cfg / "BraveSoftware" / "Brave-Browser"],
            "Brave Beta":          [cfg / "BraveSoftware" / "Brave-Browser-Beta"],
            "Brave Nightly":       [cfg / "BraveSoftware" / "Brave-Browser-Nightly"],
            "Vivaldi":             [cfg / "vivaldi"],
            "Opera":               [cfg / "opera"],
            "Yandex":              [cfg / "yandex-browser"],
        }
        for name, roots in chromium_roots.items():
            entries.append({
                "name": name, "family": "chromium",
                "user_data_dirs": roots, "profile_glob": "*",
                "db_filename": "History",
            })
        firefox_roots = {
            "Firefox":         [home / ".mozilla" / "firefox",
                                home / "snap" / "firefox" / "common" / ".mozilla" / "firefox"],
            "Firefox ESR":     [home / ".mozilla" / "firefox-esr"],
            "Waterfox":        [home / ".waterfox"],
            "LibreWolf":       [home / ".librewolf"],
            "Tor Browser":     [home / ".tor-browser" / "app" / "Browser" / "TorBrowser" / "Data" / "Browser",
                                home / ".local" / "share" / "torbrowser" / "tbb" / "x86_64" / "tor-browser" / "Browser" / "TorBrowser" / "Data" / "Browser"],
        }
        for name, roots in firefox_roots.items():
            entries.append({
                "name": name, "family": "firefox",
                "user_data_dirs": roots, "profile_glob": "*",
                "db_filename": "places.sqlite",
            })

    # ── Windows ────────────────────────────────────────────────────────────
    elif system == "windows":
        local   = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.environ.get("APPDATA",      home / "AppData" / "Roaming"))
        chromium_roots = {
            "Google Chrome":       [local   / "Google" / "Chrome" / "User Data"],
            "Google Chrome Beta":  [local   / "Google" / "Chrome Beta" / "User Data"],
            "Google Chrome Canary":[local   / "Google" / "Chrome SxS" / "User Data"],
            "Chromium":            [local   / "Chromium" / "User Data"],
            "Microsoft Edge":      [local   / "Microsoft" / "Edge" / "User Data"],
            "Microsoft Edge Beta": [local   / "Microsoft" / "Edge Beta" / "User Data"],
            "Microsoft Edge Dev":  [local   / "Microsoft" / "Edge Dev" / "User Data"],
            "Microsoft Edge Canary":[local  / "Microsoft" / "Edge SxS" / "User Data"],
            "Brave":               [local   / "BraveSoftware" / "Brave-Browser" / "User Data"],
            "Brave Beta":          [local   / "BraveSoftware" / "Brave-Browser-Beta" / "User Data"],
            "Brave Nightly":       [local   / "BraveSoftware" / "Brave-Browser-Nightly" / "User Data"],
            "Vivaldi":             [local   / "Vivaldi" / "User Data"],
            "Opera":               [roaming / "Opera Software" / "Opera Stable"],
            "Opera GX":            [roaming / "Opera Software" / "Opera GX Stable"],
            "Opera Developer":     [roaming / "Opera Software" / "Opera Developer"],
            "Yandex":              [local   / "Yandex" / "YandexBrowser" / "User Data"],
        }
        for name, roots in chromium_roots.items():
            # Opera places History at the root, not inside a profile subdir.
            profile_glob = None if "Opera" in name else "*"
            entries.append({
                "name": name, "family": "chromium",
                "user_data_dirs": roots,
                "profile_glob": profile_glob,
                "db_filename": "History",
            })
        firefox_roots = {
            "Firefox":     [roaming / "Mozilla" / "Firefox" / "Profiles"],
            "Waterfox":    [roaming / "Waterfox" / "Profiles"],
            "LibreWolf":   [roaming / "LibreWolf" / "Profiles"],
            "Tor Browser": [roaming / "Tor Browser" / "Browser" / "TorBrowser" / "Data" / "Browser"],
        }
        for name, roots in firefox_roots.items():
            entries.append({
                "name": name, "family": "firefox",
                "user_data_dirs": roots, "profile_glob": "*",
                "db_filename": "places.sqlite",
            })

    return entries


def _is_profile_dir(p: Path, family: str) -> bool:
    """
    Heuristic: is `p` plausibly a browser profile directory?

    For Chromium, real profiles are named ``Default``, ``Profile 1``, etc.,
    and contain a ``Preferences`` file. For Firefox, profiles end in
    ``.default``, ``.default-release``, etc. This filter keeps us from
    recursing into sibling dirs like ``Crash Reports``, ``ShaderCache`` …
    """
    if not p.is_dir():
        return False
    if family == "chromium":
        if p.name in {"Default", "Guest Profile", "System Profile"}:
            return True
        if p.name.startswith("Profile "):
            return True
        # Any dir carrying a Preferences file is almost certainly a profile.
        return (p / "Preferences").exists()
    if family == "firefox":
        if p.name.endswith(".default") or ".default-" in p.name:
            return True
        # Any dir containing a places.sqlite is a profile, period.
        return (p / "places.sqlite").exists()
    return True


def _discover_browser_history(errors: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Iterate every browser descriptor for this OS, open each History DB found
    in read-only mode via snapshot-copy, and return:

        {
          "history":    [ {url, title, visit_count, last_visit_at, browser, profile}, ... ],
          "by_browser": { "Google Chrome — Default": 412, "Safari": 118, ... },
          "discovered": [ {browser, profile, path, rows} ],
        }

    Errors are appended to the caller's `errors` list rather than raised so
    one locked DB never blocks the rest of the discovery pass.
    """
    registry = _browser_registry()
    history: List[Dict[str, Any]] = []
    by_browser: Dict[str, int] = {}
    discovered: List[Dict[str, Any]] = []

    for desc in registry:
        fam = desc["family"]
        db_name = desc["db_filename"]
        profile_glob = desc["profile_glob"]
        for root in desc["user_data_dirs"]:
            try:
                if not root.exists():
                    continue
            except OSError:
                continue

            # Enumerate profile directories inside `root`, or use `root` itself
            # if the descriptor says the DB sits directly in the root (Opera,
            # Safari, Tor Browser).
            if profile_glob is None:
                profile_paths = [root]
            else:
                try:
                    profile_paths = [p for p in root.iterdir() if _is_profile_dir(p, fam)]
                except OSError as e:
                    errors.append({"path": str(root), "error": f"profile enumeration failed: {e}"})
                    continue

            for prof in profile_paths:
                db_path = prof / db_name
                if not db_path.exists() or not db_path.is_file():
                    continue
                if not _is_sqlite(db_path):
                    continue
                profile_label = prof.name if prof != root else "—"
                try:
                    if fam == "chromium":
                        rows = _parse_chrome_history(db_path)
                    elif fam == "firefox":
                        rows = _parse_firefox_history(db_path)
                    elif fam == "safari":
                        rows = _parse_safari_history(db_path)
                    else:
                        continue
                except Exception as e:  # defensive — parsers should already trap
                    errors.append({"path": str(db_path), "error": f"parse failed: {e}"})
                    continue

                clean = [r for r in rows if isinstance(r, dict) and "url" in r]
                # Stamp every row with the discovered browser + profile so the
                # report can break down visits per-source.
                for r in clean:
                    r["browser"] = desc["name"]
                    r["profile"] = profile_label
                history.extend(clean)
                label = f"{desc['name']}" + (f" — {profile_label}" if profile_label != "—" else "")
                by_browser[label] = by_browser.get(label, 0) + len(clean)
                discovered.append({
                    "browser": desc["name"],
                    "profile": profile_label,
                    "path": str(db_path),
                    "rows": len(clean),
                })

    return {"history": history, "by_browser": by_browser, "discovered": discovered}


# ─────────────────────────────────────────────────────────────────────────────
# Video / audio metadata probe (ffprobe if available)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_media_metadata(path: Path) -> Dict[str, Any]:
    """
    Best-effort probe of a video/audio file. Uses ffprobe if it's on PATH
    (optional — the scanner works fine without it). Returns codec, duration,
    and frame-rate when available.
    """
    from shutil import which
    if not which("ffprobe"):
        return {}
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "error", "-show_format", "-show_streams",
             "-print_format", "json", str(path)],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return {}
        data = json.loads(out.stdout)
        fmt = data.get("format", {}) or {}
        streams = data.get("streams", []) or []
        video = next((s for s in streams if s.get("codec_type") == "video"), None)
        audio = next((s for s in streams if s.get("codec_type") == "audio"), None)
        return {
            "duration_seconds": float(fmt["duration"]) if fmt.get("duration") else None,
            "bitrate": int(fmt["bit_rate"]) if fmt.get("bit_rate") else None,
            "video_codec": video.get("codec_name") if video else None,
            "audio_codec": audio.get("codec_name") if audio else None,
            "width":  video.get("width")  if video else None,
            "height": video.get("height") if video else None,
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────


def scan(
    root: Path,
    *,
    rar_decision: Optional[RarDecisionFn] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    include_browsers: bool = False,
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
    include_browsers
        When True, parse in-tree browser History/places.sqlite files AND run
        a system-wide discovery pass over Chrome/Edge/Firefox/Brave/Opera
        profiles. When False (the default), browser databases are simply
        listed as "browser_db" entries with a note — no parsing, no URLs,
        no discovery. This lets the investigator run a metadata-only scan
        on sensitive machines without exposing visited URLs.
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
        # Browser history rows extracted locally from Chrome/Edge/Firefox DBs.
        # Kept as a flat list so the backend can render a unified timeline
        # without having to re-open per-file entries.
        "browser_history": [],
        # Video files with ffprobe-extracted metadata (codec, duration, dims).
        # Flat list for the "Videos" section of the interactive report.
        "videos": [],
        "errors": [],
        "summary": {
            "total_files": 0, "total_size_bytes": 0,
            "by_type": {}, "with_exif": 0, "with_text": 0,
            "with_history": 0, "history_rows": 0,
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
            entry = _process_file(
                path,
                include_rar=include_rar,
                root=root,
                include_browsers=include_browsers,
            )
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
            # Browser history rows bubble up from _process_file() when it's
            # pointed at a Chrome/Edge/Firefox profile DB. We keep a flat
            # top-level list so downstream code doesn't have to walk files[].
            hist = entry.get("history_entries")
            if hist:
                # Filter out the "error" stub rows — they stay inside the
                # per-file entry for debugging but shouldn't pollute the
                # unified timeline.
                clean = [h for h in hist if isinstance(h, dict) and "url" in h]
                if clean:
                    findings["browser_history"].extend(clean)
                    findings["summary"]["with_history"] += 1
                    findings["summary"]["history_rows"] += len(clean)
            # Surface videos with their probed metadata in a dedicated list
            # so the report can render a "Videos" gallery.
            if entry["type"] == "video" and entry.get("media"):
                findings["videos"].append({
                    "path": entry["path"],
                    "name": entry["name"],
                    "size": entry.get("size"),
                    "md5": entry.get("md5"),
                    "sha256": entry.get("sha256"),
                    **entry["media"],
                })
        except Exception as e:
            findings["errors"].append({"path": str(path), "error": str(e)})
        if on_progress:
            on_progress(i, total)

    # ── System-wide browser-history discovery ──────────────────────────────
    # Independent of what the investigator asked us to walk. When enabled,
    # we check every supported browser on the host so the report can answer
    # "what did this user do online?" even when the scan target is, say,
    # Downloads. Rows are de-duplicated against any DBs the file walk
    # happened to surface, keyed on (url, last_visit_at, browser).
    #
    # Gated by include_browsers (opt-in). A default scan never touches the
    # user's browser profiles — investigator must explicitly enable it.
    if include_browsers:
        try:
            discovery = _discover_browser_history(findings["errors"])
        except Exception as e:  # pragma: no cover — defensive
            findings["errors"].append({"path": "<browser-discovery>", "error": str(e)})
            discovery = {"history": [], "by_browser": {}, "discovered": []}
    else:
        discovery = {"history": [], "by_browser": {}, "discovered": []}
        findings["summary"]["browsers_skipped"] = True

    seen: set = {
        (h.get("url"), h.get("last_visit_at"), h.get("browser"))
        for h in findings["browser_history"]
    }
    added = 0
    for row in discovery["history"]:
        key = (row.get("url"), row.get("last_visit_at"), row.get("browser"))
        if key in seen:
            continue
        seen.add(key)
        findings["browser_history"].append(row)
        added += 1

    findings["summary"]["history_rows"] = len(findings["browser_history"])
    findings["summary"]["with_history"] = (
        findings["summary"].get("with_history", 0) + len(discovery["discovered"])
    )
    # Per-browser breakdown — surfaced directly in the report's Web Activity
    # card. We also expose the list of discovered DB paths for the forensic
    # annex (investigator-only, scrubbed from the client view).
    findings["summary"]["browsers_discovered"] = len(discovery["discovered"])
    findings["summary"]["history_by_browser"] = discovery["by_browser"]
    findings["browser_sources"] = discovery["discovered"]

    findings["summary"]["total_files"] = len(findings["files"])
    findings["summary"]["by_type"] = by_type
    return findings


def _process_file(
    path: Path,
    *,
    include_rar: bool,
    root: Path,
    include_browsers: bool = False,
) -> Optional[Dict[str, Any]]:
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
    elif ftype == "browser_db":
        # Parses Chrome/Edge/Brave/Opera `History` and Firefox `places.sqlite`
        # in-place. Returns {browser, history_entries} or {note} when parsing
        # is declined (e.g. Cookies / Login Data for privacy reasons).
        # Gated by include_browsers so a privacy-conscious run doesn't expose
        # visited URLs just because the walker stumbled on a History file.
        if include_browsers:
            entry.update(_extract_browser_history(path))
        else:
            entry["note"] = "Browser database — parsing skipped (browser history disabled)."
    elif ftype == "sqlite":
        # Generic SQLite file — don't enumerate its tables by default
        # (could contain anything). Flag it so the investigator sees it.
        if _is_sqlite(path):
            entry["note"] = "SQLite database — skipped generic parsing. Inspect manually."
        else:
            entry["note"] = "Named like a SQLite DB but magic bytes don't match."
    elif ftype == "video":
        meta = _extract_media_metadata(path)
        if meta:
            entry["media"] = meta
    elif ftype == "audio":
        meta = _extract_media_metadata(path)
        if meta:
            entry["media"] = meta

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
