"""
artifact_extractor.py — Artifact Extraction Module
Extracts browser history, EXIF metadata, multimedia files, and documents.
"""

import os
import re
import json
import sqlite3
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class ArtifactExtractor:
    """
    Extracts forensic artifacts from recovered files.
    Handles: browser history, EXIF metadata, multimedia, documents.
    """

    IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"}
    VIDEO_EXTS = {".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm"}
    DOC_EXTS   = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".txt", ".csv", ".rtf"}

    def __init__(self, recovered_path: str, evidence_path: str = ""):
        self.recovered_path = Path(recovered_path)
        self.evidence_path = Path(evidence_path) if evidence_path else None
        self.exiftool_available = shutil.which("exiftool") is not None
        self.photorec_available = shutil.which("photorec") is not None
        self.foremost_available = shutil.which("foremost") is not None

    # ──────────────────────────────────────────────────────────
    # Browser History Extraction
    # ──────────────────────────────────────────────────────────

    def extract_browser_history(self) -> List[Dict]:
        """Extract browser history from recovered SQLite databases."""
        history = []
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                
                # Chrome History
                if fname.lower() == "history" and self._is_sqlite(fpath):
                    chrome_history = self._parse_chrome_history(fpath)
                    history.extend(chrome_history)
                
                # Firefox places.sqlite
                if fname.lower() == "places.sqlite":
                    firefox_history = self._parse_firefox_history(fpath)
                    history.extend(firefox_history)
                
                # Edge (also Chromium-based History db)
                if fname.lower() == "history" and "edge" in str(root).lower():
                    edge_history = self._parse_chrome_history(fpath)
                    history.extend(edge_history)
        
        return history[:500]  # Cap at 500 entries

    def _is_sqlite(self, path: Path) -> bool:
        """Check if a file is a SQLite database by magic bytes."""
        try:
            with open(str(path), "rb") as f:
                return f.read(16).startswith(b"SQLite format 3")
        except Exception:
            return False

    def _parse_chrome_history(self, db_path: Path) -> List[Dict]:
        """Parse Chrome/Chromium History SQLite database."""
        entries = []
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    u.url,
                    u.title,
                    u.visit_count,
                    v.visit_time
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                ORDER BY v.visit_time DESC
                LIMIT 500
            """)
            
            for row in cur.fetchall():
                visit_time = None
                if row["visit_time"]:
                    # Chrome timestamps: microseconds since 1601-01-01
                    try:
                        ts = (row["visit_time"] / 1_000_000) - 11644473600
                        visit_time = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        visit_time = str(row["visit_time"])
                
                entries.append({
                    "browser": "Chrome/Chromium",
                    "url": row["url"] or "",
                    "title": row["title"] or "",
                    "visit_count": row["visit_count"] or 0,
                    "visit_time": visit_time or "Unknown",
                    "source": str(db_path)
                })
            
            conn.close()
        except Exception as e:
            entries.append({
                "browser": "Chrome (error)",
                "url": f"Error reading: {e}",
                "title": "",
                "visit_count": 0,
                "visit_time": "Unknown",
                "source": str(db_path)
            })
        
        return entries

    def _parse_firefox_history(self, db_path: Path) -> List[Dict]:
        """Parse Firefox places.sqlite database."""
        entries = []
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    p.url,
                    p.title,
                    p.visit_count,
                    h.visit_date
                FROM moz_places p
                LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                ORDER BY h.visit_date DESC
                LIMIT 500
            """)
            
            for row in cur.fetchall():
                visit_time = None
                if row["visit_date"]:
                    try:
                        ts = row["visit_date"] / 1_000_000
                        visit_time = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        visit_time = str(row["visit_date"])
                
                entries.append({
                    "browser": "Firefox",
                    "url": row["url"] or "",
                    "title": row["title"] or "",
                    "visit_count": row["visit_count"] or 0,
                    "visit_time": visit_time or "Unknown",
                    "source": str(db_path)
                })
            
            conn.close()
        except Exception as e:
            entries.append({
                "browser": "Firefox (error)",
                "url": f"Error reading: {e}",
                "title": "",
                "visit_count": 0,
                "visit_time": "Unknown",
                "source": str(db_path)
            })
        
        return entries

    # ──────────────────────────────────────────────────────────
    # Metadata Extraction (exiftool)
    # ──────────────────────────────────────────────────────────

    def extract_metadata(self) -> List[Dict]:
        """Extract EXIF/metadata from image files using exiftool."""
        metadata_list = []
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in self.IMAGE_EXTS:
                    meta = self._extract_file_metadata(fpath)
                    if meta:
                        metadata_list.append(meta)
        
        return metadata_list[:200]

    def _extract_file_metadata(self, file_path: Path) -> Optional[Dict]:
        """Extract metadata from a single file using exiftool."""
        if self.exiftool_available:
            try:
                result = subprocess.run(
                    ["exiftool", "-json", "-GPS*", "-Make", "-Model", 
                     "-SerialNumber", "-DateTimeOriginal", "-CreateDate",
                     "-ModifyDate", "-Software", "-Artist", str(file_path)],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    if data:
                        meta = data[0]
                        return {
                            "file": str(file_path),
                            "filename": file_path.name,
                            "make": meta.get("Make", ""),
                            "model": meta.get("Model", ""),
                            "serial_number": meta.get("SerialNumber", ""),
                            "datetime_original": meta.get("DateTimeOriginal", ""),
                            "create_date": meta.get("CreateDate", ""),
                            "modify_date": meta.get("ModifyDate", ""),
                            "gps_latitude": meta.get("GPSLatitude", ""),
                            "gps_longitude": meta.get("GPSLongitude", ""),
                            "gps_position": meta.get("GPSPosition", ""),
                            "software": meta.get("Software", ""),
                            "raw": meta
                        }
            except Exception:
                pass
        
        # Fallback: Basic file metadata
        try:
            stat = os.stat(str(file_path))
            return {
                "file": str(file_path),
                "filename": file_path.name,
                "make": "",
                "model": "",
                "serial_number": "",
                "datetime_original": "",
                "create_date": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                "modify_date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "gps_latitude": "",
                "gps_longitude": "",
                "gps_position": "",
                "software": "",
                "raw": {}
            }
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────
    # Multimedia Detection
    # ──────────────────────────────────────────────────────────

    def extract_multimedia(self) -> List[Dict]:
        """Detect and catalog all multimedia files in recovered directory."""
        multimedia = []
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                
                if ext in self.IMAGE_EXTS:
                    multimedia.append({
                        "type": "image",
                        "filename": fname,
                        "path": str(fpath),
                        "relative_path": str(fpath.relative_to(self.recovered_path)),
                        "size": os.path.getsize(str(fpath)) if fpath.exists() else 0,
                        "extension": ext
                    })
                elif ext in self.VIDEO_EXTS:
                    multimedia.append({
                        "type": "video",
                        "filename": fname,
                        "path": str(fpath),
                        "relative_path": str(fpath.relative_to(self.recovered_path)),
                        "size": os.path.getsize(str(fpath)) if fpath.exists() else 0,
                        "extension": ext
                    })
        
        return multimedia[:300]

    # ──────────────────────────────────────────────────────────
    # Document Detection
    # ──────────────────────────────────────────────────────────

    def extract_documents(self) -> List[Dict]:
        """Detect and catalog document files."""
        documents = []
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                
                if ext in self.DOC_EXTS:
                    documents.append({
                        "type": "document",
                        "filename": fname,
                        "path": str(fpath),
                        "relative_path": str(fpath.relative_to(self.recovered_path)),
                        "size": os.path.getsize(str(fpath)) if fpath.exists() else 0,
                        "extension": ext,
                        "doc_type": self._classify_doc(ext)
                    })
        
        return documents[:300]

    def _classify_doc(self, ext: str) -> str:
        """Classify document type."""
        if ext == ".pdf": return "PDF"
        if ext in {".docx", ".doc"}: return "Word Document"
        if ext in {".xlsx", ".xls"}: return "Spreadsheet"
        if ext in {".pptx", ".ppt"}: return "Presentation"
        if ext == ".txt": return "Text File"
        if ext == ".csv": return "CSV Data"
        return "Document"

    # ──────────────────────────────────────────────────────────
    # Media Carving
    # ──────────────────────────────────────────────────────────

    def run_media_carving(self, output_dir: str) -> Dict:
        """
        Run file carving using photorec or foremost.
        Returns summary of carved files.
        """
        if not self.evidence_path or not self.evidence_path.exists():
            return {"status": "skipped", "reason": "No evidence path for carving"}

        carved_dir = Path(output_dir) / "carved"
        carved_dir.mkdir(parents=True, exist_ok=True)
        
        # Try photorec first
        if self.photorec_available:
            try:
                result = subprocess.run(
                    ["photorec", "/d", str(carved_dir), "/cmd",
                     str(self.evidence_path), "fileopt,enable,everything,quit"],
                    capture_output=True, text=True, timeout=300
                )
                carved_files = list(carved_dir.rglob("*.*"))
                return {
                    "status": "completed",
                    "tool": "photorec",
                    "carved_count": len(carved_files),
                    "output_dir": str(carved_dir)
                }
            except Exception as e:
                pass
        
        # Try foremost
        if self.foremost_available:
            try:
                result = subprocess.run(
                    ["foremost", "-o", str(carved_dir), str(self.evidence_path)],
                    capture_output=True, text=True, timeout=300
                )
                carved_files = list(carved_dir.rglob("*.*"))
                return {
                    "status": "completed",
                    "tool": "foremost",
                    "carved_count": len(carved_files),
                    "output_dir": str(carved_dir)
                }
            except Exception as e:
                pass
        
        return {
            "status": "skipped",
            "reason": "Neither photorec nor foremost is installed"
        }

    # ──────────────────────────────────────────────────────────
    # Master Extract
    # ──────────────────────────────────────────────────────────

    def extract_all(self) -> Dict:
        """Run all artifact extraction methods and return consolidated results."""
        return {
            "browser_history": self.extract_browser_history(),
            "metadata": self.extract_metadata(),
            "multimedia": self.extract_multimedia(),
            "documents": self.extract_documents(),
            "carving": {},  # Run separately if needed
        }
