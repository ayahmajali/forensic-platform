"""
timeline_builder.py — Forensic Timeline Builder
Uses fls + mactime to generate MAC-time activity timeline.
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict
from datetime import datetime


class TimelineBuilder:
    """
    Builds forensic timeline using Sleuth Kit's fls and mactime tools.
    Falls back to filesystem-based timeline if TSK not available.
    """

    def __init__(self, image_path: str, recovered_path: str):
        self.image_path = Path(image_path)
        self.recovered_path = Path(recovered_path)
        self.tsk_available = shutil.which("fls") is not None
        self.mactime_available = shutil.which("mactime") is not None

    def _run_cmd(self, cmd: List[str], timeout: int = 180) -> tuple:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace"
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1

    def build_tsk_timeline(self, offset: int = 0) -> List[Dict]:
        """
        Build timeline using fls -r -m and mactime.
        """
        events = []
        
        if not self.tsk_available:
            return events
        
        # Generate body file with fls
        fls_cmd = ["fls", "-r", "-m", "/"]
        if offset > 0:
            fls_cmd += ["-o", str(offset)]
        fls_cmd.append(str(self.image_path))
        
        fls_out, fls_err, fls_rc = self._run_cmd(fls_cmd)
        
        if not fls_out:
            return events
        
        # Write body file
        body_file = self.recovered_path / "timeline.body"
        with open(str(body_file), "w", encoding="utf-8", errors="replace") as f:
            f.write(fls_out)
        
        if self.mactime_available:
            # Run mactime
            mactime_cmd = ["mactime", "-b", str(body_file), "-d"]
            mac_out, mac_err, mac_rc = self._run_cmd(mactime_cmd)
            
            if mac_out:
                events = self._parse_mactime_output(mac_out)
        
        # If mactime not available, parse body file directly
        if not events and fls_out:
            events = self._parse_body_file(fls_out)
        
        return events

    def _parse_mactime_output(self, output: str) -> List[Dict]:
        """Parse mactime -d (CSV) output."""
        events = []
        lines = output.strip().split("\n")
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            parts = line.split(",", 5)
            if len(parts) >= 5:
                try:
                    events.append({
                        "date": parts[0].strip().strip('"'),
                        "size": parts[1].strip().strip('"'),
                        "activity": parts[2].strip().strip('"'),
                        "permissions": parts[3].strip().strip('"'),
                        "inode": parts[4].strip().strip('"'),
                        "filename": parts[5].strip().strip('"') if len(parts) > 5 else "",
                        "source": "mactime"
                    })
                except (IndexError, ValueError):
                    continue
        
        return events[:2000]

    def _parse_body_file(self, body_content: str) -> List[Dict]:
        """
        Parse fls body file format directly.
        Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        """
        events = []
        
        for line in body_content.strip().split("\n"):
            if not line.strip():
                continue
            
            parts = line.split("|")
            if len(parts) >= 11:
                try:
                    name = parts[1]
                    size = parts[6]
                    mtime = self._ts_to_date(parts[8])
                    ctime = self._ts_to_date(parts[9])
                    atime = self._ts_to_date(parts[7])
                    
                    if mtime:
                        events.append({
                            "date": mtime,
                            "activity": "M",
                            "filename": name,
                            "size": size,
                            "inode": parts[2],
                            "atime": atime,
                            "ctime": ctime,
                            "source": "fls-body"
                        })
                except (IndexError, ValueError):
                    continue
        
        # Sort by date
        events.sort(key=lambda x: x.get("date", ""), reverse=True)
        return events[:2000]

    def _ts_to_date(self, ts_str: str) -> str:
        """Convert Unix timestamp to readable date."""
        try:
            ts = int(ts_str)
            if ts <= 0:
                return ""
            return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    def build_filesystem_timeline(self) -> List[Dict]:
        """
        Build timeline from recovered filesystem timestamps.
        Fallback when TSK tools are not available.
        """
        events = []
        
        for root, dirs, files in os.walk(str(self.recovered_path)):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    stat = os.stat(str(fpath))
                    
                    events.append({
                        "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "activity": "M",
                        "filename": str(fpath.relative_to(self.recovered_path)),
                        "size": str(stat.st_size),
                        "inode": str(stat.st_ino),
                        "atime": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
                        "ctime": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "filesystem"
                    })
                except Exception:
                    continue
        
        events.sort(key=lambda x: x.get("date", ""), reverse=True)
        return events[:2000]

    def build_timeline(self, offset: int = 0) -> List[Dict]:
        """
        Build forensic timeline using best available method.
        """
        if self.tsk_available and self.image_path.exists() and self.image_path.is_file():
            timeline = self.build_tsk_timeline(offset)
            if timeline:
                return timeline
        
        # Fallback to filesystem timeline
        return self.build_filesystem_timeline()
