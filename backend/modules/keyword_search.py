"""
keyword_search.py — Forensic Keyword Search Engine
Searches file content, browser history, metadata, and extracted strings.
"""

import os
import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional


class KeywordSearchEngine:
    """
    Powerful forensic keyword search across:
    - File names and extensions
    - File content (text files, strings)
    - Browser history URLs and titles
    - EXIF metadata
    - Extracted strings
    """

    TEXT_EXTS = {
        ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm",
        ".ini", ".cfg", ".conf", ".bat", ".ps1", ".sh", ".py",
        ".js", ".php", ".sql", ".md", ".yaml", ".yml", ".env"
    }

    def __init__(self, recovered_path: str, artifacts: Dict):
        self.recovered_path = Path(recovered_path)
        self.artifacts = artifacts

    # ──────────────────────────────────────────────────────────
    # Core Search Methods
    # ──────────────────────────────────────────────────────────

    def search_filenames(self, keyword: str) -> List[Dict]:
        """Search for keyword in file names."""
        results = []
        kw_lower = keyword.lower()
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                
                # Match by name or extension
                if kw_lower in fname.lower():
                    results.append({
                        "match_type": "filename",
                        "keyword": keyword,
                        "file": str(fpath.relative_to(self.recovered_path) 
                                   if fpath.is_relative_to(self.recovered_path) else fpath),
                        "context": f"Filename: {fname}",
                        "line_number": None,
                        "source": "filesystem"
                    })
        
        return results[:100]

    def search_file_content(self, keyword: str) -> List[Dict]:
        """Search inside text file contents for keyword."""
        results = []
        kw_lower = keyword.lower()
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                
                if fpath.suffix.lower() not in self.TEXT_EXTS:
                    continue
                
                if os.path.getsize(str(fpath)) > 10 * 1024 * 1024:  # Skip files > 10MB
                    continue
                
                try:
                    with open(str(fpath), "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                    
                    for i, line in enumerate(lines, 1):
                        if kw_lower in line.lower():
                            context = line.strip()[:200]
                            results.append({
                                "match_type": "content",
                                "keyword": keyword,
                                "file": str(fpath.relative_to(self.recovered_path)
                                           if fpath.is_relative_to(self.recovered_path) else fpath),
                                "context": context,
                                "line_number": i,
                                "source": "file_content"
                            })
                            
                            if len(results) >= 200:  # Cap content hits
                                return results
                except Exception:
                    continue
        
        return results

    def search_browser_history(self, keyword: str) -> List[Dict]:
        """Search browser history URLs and titles."""
        results = []
        kw_lower = keyword.lower()
        history = self.artifacts.get("browser_history", [])
        
        for entry in history:
            url = entry.get("url", "").lower()
            title = entry.get("title", "").lower()
            
            if kw_lower in url or kw_lower in title:
                results.append({
                    "match_type": "browser_history",
                    "keyword": keyword,
                    "file": entry.get("source", "browser_history"),
                    "context": f"[{entry.get('browser','')}] {entry.get('url','')} — {entry.get('title','')}",
                    "line_number": None,
                    "visit_time": entry.get("visit_time", ""),
                    "source": "browser"
                })
        
        return results[:100]

    def search_metadata(self, keyword: str) -> List[Dict]:
        """Search EXIF metadata for keyword."""
        results = []
        kw_lower = keyword.lower()
        metadata_list = self.artifacts.get("metadata", [])
        
        for meta in metadata_list:
            raw = meta.get("raw", {})
            for key, value in raw.items():
                if kw_lower in str(value).lower() or kw_lower in str(key).lower():
                    results.append({
                        "match_type": "metadata",
                        "keyword": keyword,
                        "file": meta.get("filename", ""),
                        "context": f"{key}: {value}",
                        "line_number": None,
                        "source": "exif_metadata"
                    })
        
        return results[:50]

    def search_sqlite_databases(self, keyword: str) -> List[Dict]:
        """Search SQLite databases for keyword in string columns."""
        results = []
        kw_lower = keyword.lower()
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                if not self._is_sqlite(fpath):
                    continue
                
                try:
                    conn = sqlite3.connect(str(fpath))
                    cur = conn.cursor()
                    
                    # Get all tables
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [t[0] for t in cur.fetchall()]
                    
                    for table in tables[:20]:  # Limit tables
                        try:
                            cur.execute(f"SELECT * FROM [{table}] LIMIT 1000")
                            rows = cur.fetchall()
                            cols = [desc[0] for desc in cur.description] if cur.description else []
                            
                            for row in rows:
                                for i, cell in enumerate(row):
                                    if kw_lower in str(cell).lower():
                                        col_name = cols[i] if i < len(cols) else f"col_{i}"
                                        results.append({
                                            "match_type": "database",
                                            "keyword": keyword,
                                            "file": f"{fname} → {table}.{col_name}",
                                            "context": str(cell)[:200],
                                            "line_number": None,
                                            "source": "sqlite"
                                        })
                                        if len(results) >= 50:
                                            conn.close()
                                            return results
                        except Exception:
                            continue
                    
                    conn.close()
                except Exception:
                    continue
        
        return results

    def search_emails(self, keyword: str = "") -> List[Dict]:
        """Extract all email addresses from recovered files."""
        results = []
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        kw_filter = keyword.lower() if keyword else ""
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                
                if fpath.suffix.lower() not in self.TEXT_EXTS:
                    continue
                
                if os.path.getsize(str(fpath)) > 5 * 1024 * 1024:
                    continue
                
                try:
                    with open(str(fpath), "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    
                    emails_found = set(email_pattern.findall(content))
                    
                    for email in emails_found:
                        if not kw_filter or kw_filter in email.lower():
                            results.append({
                                "match_type": "email",
                                "keyword": email,
                                "file": fname,
                                "context": f"Email found: {email}",
                                "line_number": None,
                                "source": "email_extract"
                            })
                except Exception:
                    continue
                
                if len(results) >= 100:
                    break
        
        return results

    def search_urls(self, keyword: str = "") -> List[Dict]:
        """Extract URLs from recovered files and browser history."""
        results = []
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        kw_filter = keyword.lower() if keyword else ""
        
        # Search file content
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                
                if fpath.suffix.lower() not in self.TEXT_EXTS:
                    continue
                
                if os.path.getsize(str(fpath)) > 5 * 1024 * 1024:
                    continue
                
                try:
                    with open(str(fpath), "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    
                    urls_found = set(url_pattern.findall(content))
                    
                    for url in urls_found:
                        if not kw_filter or kw_filter in url.lower():
                            results.append({
                                "match_type": "url",
                                "keyword": url[:100],
                                "file": fname,
                                "context": f"URL found: {url[:200]}",
                                "line_number": None,
                                "source": "url_extract"
                            })
                except Exception:
                    continue
                
                if len(results) >= 200:
                    return results
        
        return results

    def _is_sqlite(self, path: Path) -> bool:
        """Check if a file is SQLite by magic bytes."""
        try:
            with open(str(path), "rb") as f:
                return f.read(16).startswith(b"SQLite format 3")
        except Exception:
            return False

    # ──────────────────────────────────────────────────────────
    # Master Search
    # ──────────────────────────────────────────────────────────

    def search_all(self, keywords: List[str]) -> Dict[str, List[Dict]]:
        """
        Run all search methods for each keyword.
        Returns dict: {keyword: [result, ...]}
        """
        all_results = {}
        
        for keyword in keywords:
            if not keyword.strip():
                continue
            
            kw = keyword.strip()
            hits = []
            
            # Detect search type
            if "@" in kw and "." in kw:
                # Looks like email search
                hits.extend(self.search_emails(kw))
            elif kw.startswith(".") and len(kw) <= 6:
                # Extension search
                hits.extend(self.search_filenames(kw))
            elif kw.startswith("http") or kw.startswith("www"):
                # URL search
                hits.extend(self.search_urls(kw))
            else:
                # General search
                hits.extend(self.search_filenames(kw))
                hits.extend(self.search_file_content(kw))
                hits.extend(self.search_browser_history(kw))
                hits.extend(self.search_metadata(kw))
            
            # Deduplicate
            seen = set()
            unique_hits = []
            for h in hits:
                key = (h.get("file", ""), h.get("context", "")[:50])
                if key not in seen:
                    seen.add(key)
                    unique_hits.append(h)
            
            all_results[kw] = unique_hits[:100]  # Cap per keyword
        
        return all_results

    def search_single(self, keyword: str) -> List[Dict]:
        """Search for a single keyword across all sources."""
        results = self.search_all([keyword])
        return results.get(keyword, [])
