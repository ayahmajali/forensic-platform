"""
disk_analysis.py — Disk Image Analysis Module
Runs Sleuth Kit tools: mmls, fsstat, fls, ils, tsk_recover
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class DiskAnalyzer:
    """
    Performs comprehensive disk image analysis using The Sleuth Kit (TSK).
    Supports: E01, DD, RAW, ISO, IMG disk images.
    """

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.tsk_available = self._check_tsk()

    def _check_tsk(self) -> bool:
        """Check if Sleuth Kit tools are installed."""
        return shutil.which("mmls") is not None or shutil.which("fls") is not None

    def _run_cmd(self, cmd: List[str], timeout: int = 120) -> Tuple[str, str, int]:
        """Run a system command and return stdout, stderr, returncode."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace"
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    def run_mmls(self) -> Dict:
        """
        Run mmls to detect disk partitions.
        Returns partition table information.
        """
        stdout, stderr, rc = self._run_cmd(["mmls", str(self.image_path)])
        
        partitions = []
        raw_output = stdout or stderr
        
        if stdout:
            lines = stdout.strip().split("\n")
            for line in lines[2:]:  # Skip header lines
                # Parse mmls output: slot, start, end, length, description
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        slot = parts[0].rstrip(":")
                        start = int(parts[1])
                        end = int(parts[2])
                        length = int(parts[3])
                        desc = " ".join(parts[4:])
                        partitions.append({
                            "slot": slot,
                            "start": start,
                            "end": end,
                            "length": length,
                            "description": desc,
                            "offset": start * 512,  # bytes offset
                        })
                    except (ValueError, IndexError):
                        continue
        
        # If no partitions found, try offset 0
        if not partitions:
            partitions = [{
                "slot": "0",
                "start": 0,
                "end": 0,
                "length": 0,
                "description": "Primary partition (assumed)",
                "offset": 0,
            }]
        
        return {
            "raw": raw_output,
            "partitions": partitions,
            "count": len(partitions)
        }

    def get_primary_offset(self, partitions: List[Dict]) -> int:
        """
        Extract the most likely primary partition offset.
        Filters out metadata partitions and returns start sector.
        """
        for p in partitions:
            desc = p.get("description", "").lower()
            # Skip unallocated, extended, metadata
            if any(x in desc for x in ["unallocated", "extended", "meta", "empty"]):
                continue
            if p["start"] > 0:
                return p["start"]
        
        # Fallback: first partition with data
        for p in partitions:
            if p["start"] > 0:
                return p["start"]
        
        return 0

    def run_fsstat(self, offset: int = 0) -> Dict:
        """
        Run fsstat to get filesystem information.
        """
        cmd = ["fsstat"]
        if offset > 0:
            cmd += ["-o", str(offset)]
        cmd.append(str(self.image_path))
        
        stdout, stderr, rc = self._run_cmd(cmd)
        raw = stdout or stderr
        
        fs_info = {
            "raw": raw,
            "fs_type": "unknown",
            "volume_name": "",
            "last_mount": "",
            "block_size": "",
            "block_count": "",
        }
        
        if stdout:
            # Parse filesystem type
            for line in stdout.split("\n"):
                line_lower = line.lower()
                if "file system type:" in line_lower or "type:" in line_lower:
                    fs_info["fs_type"] = line.split(":")[-1].strip()
                elif "volume name:" in line_lower:
                    fs_info["volume_name"] = line.split(":")[-1].strip()
                elif "last mount" in line_lower:
                    fs_info["last_mount"] = line.split(":")[-1].strip()
                elif "block size:" in line_lower:
                    fs_info["block_size"] = line.split(":")[-1].strip()
                elif "block count:" in line_lower:
                    fs_info["block_count"] = line.split(":")[-1].strip()
        
        return fs_info

    def run_fls(self, offset: int = 0, deleted_only: bool = False) -> List[Dict]:
        """
        Run fls to list files in the filesystem.
        deleted_only=True uses -rd flag to list only deleted files.
        """
        cmd = ["fls", "-r"]
        if deleted_only:
            cmd.append("-d")
        if offset > 0:
            cmd += ["-o", str(offset)]
        cmd.append(str(self.image_path))
        
        stdout, stderr, rc = self._run_cmd(cmd, timeout=180)
        
        files = []
        if stdout:
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue
                # fls format: type/name  inode  path
                # d/d = directory, r/r = regular, r/- = deleted file
                file_entry = self._parse_fls_line(line, deleted_only)
                if file_entry:
                    files.append(file_entry)
        
        return files

    def _parse_fls_line(self, line: str, is_deleted_context: bool = False) -> Optional[Dict]:
        """Parse a single fls output line."""
        try:
            # fls format: r/r 1234-128-1: filename
            #             r/- 1234-128-1: filename (deleted)
            match = re.match(r'^([dr])/([dr\-])\s+(\S+):\s+(.+)$', line.strip())
            if not match:
                # Try alternate format
                parts = line.split()
                if len(parts) >= 2:
                    return {
                        "type": "file",
                        "inode": parts[0] if parts else "",
                        "name": " ".join(parts[1:]).strip(":"),
                        "deleted": is_deleted_context or "/" in parts[0] and "-" in parts[0],
                        "raw": line
                    }
                return None
            
            type_char = match.group(1)
            status_char = match.group(2)
            inode = match.group(3)
            name = match.group(4)
            
            is_deleted = status_char == "-"
            entry_type = "directory" if type_char == "d" else "file"
            
            return {
                "type": entry_type,
                "inode": inode,
                "name": name,
                "deleted": is_deleted,
                "raw": line
            }
        except Exception:
            return None

    def run_ils(self, offset: int = 0) -> List[Dict]:
        """
        Run ils to get inode listing.
        """
        cmd = ["ils"]
        if offset > 0:
            cmd += ["-o", str(offset)]
        cmd.append(str(self.image_path))
        
        stdout, stderr, rc = self._run_cmd(cmd, timeout=120)
        
        inodes = []
        if stdout:
            for line in stdout.strip().split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("|")
                if len(parts) >= 3:
                    inodes.append({
                        "inode": parts[0].strip() if len(parts) > 0 else "",
                        "status": parts[1].strip() if len(parts) > 1 else "",
                        "links": parts[2].strip() if len(parts) > 2 else "",
                        "raw": line
                    })
        
        return inodes

    def recover_files(self, output_dir: str, offset: int = 0) -> List[str]:
        """
        Recover files using tsk_recover.
        Returns list of recovered file paths.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        cmd = ["tsk_recover"]
        if offset > 0:
            cmd += ["-o", str(offset)]
        cmd += [str(self.image_path), str(output_path)]
        
        stdout, stderr, rc = self._run_cmd(cmd, timeout=300)
        
        # Collect recovered files
        recovered = []
        for root, dirs, files in os.walk(str(output_path)):
            for fname in files:
                fpath = os.path.join(root, fname)
                recovered.append(fpath)
        
        return recovered

    def run_full_disk_analysis(self) -> Dict:
        """
        Run complete disk analysis pipeline.
        Returns consolidated results dictionary.
        """
        results = {
            "image_path": str(self.image_path),
            "tsk_available": self.tsk_available,
        }

        if not self.tsk_available:
            results["error"] = "Sleuth Kit not installed. Install TSK to enable disk analysis."
            results["partitions"] = []
            results["all_files"] = []
            results["deleted_files"] = []
            results["inodes"] = []
            results["offset"] = 0
            results["fsstat"] = {"raw": "TSK not available", "fs_type": "unknown"}
            return results

        # Run mmls
        mmls_result = self.run_mmls()
        results["partitions"] = mmls_result["partitions"]
        results["mmls_raw"] = mmls_result["raw"]
        
        # Get primary partition offset
        offset = self.get_primary_offset(mmls_result["partitions"])
        results["offset"] = offset
        
        # Run fsstat
        results["fsstat"] = self.run_fsstat(offset)
        
        # Run fls (all files)
        all_files = self.run_fls(offset, deleted_only=False)
        results["all_files"] = all_files[:5000]  # Cap at 5000
        results["total_files"] = len(all_files)
        
        # Run fls (deleted files)
        deleted_files = self.run_fls(offset, deleted_only=True)
        results["deleted_files"] = deleted_files[:2000]
        results["total_deleted"] = len(deleted_files)
        
        # Run ils (inode listing)
        inodes = self.run_ils(offset)
        results["inodes"] = inodes[:1000]
        results["total_inodes"] = len(inodes)
        
        return results
