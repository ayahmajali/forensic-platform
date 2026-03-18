"""
analyzer.py — Core Evidence Analyzer
Handles evidence type detection and hash computation.
"""

import os
import hashlib
import subprocess
import struct
from pathlib import Path
from typing import Dict, Optional


class ForensicAnalyzer:
    """
    Main forensic analyzer class.
    Detects evidence type and computes cryptographic hashes.
    """

    DISK_IMAGE_SIGNATURES = {
        "e01": b"EVF",
        "vmdk": b"KDMV",
        "vhd": b"conectix",
        "iso": b"\x00CD001",
    }

    def __init__(self, evidence_path: str):
        self.evidence_path = Path(evidence_path)
        if not self.evidence_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {evidence_path}")

    def detect_evidence_type(self) -> str:
        """
        Detect the type of evidence based on file extension and magic bytes.
        Returns: 'disk_image', 'logical_file', 'e01', 'dd', 'raw', 'iso'
        """
        ext = self.evidence_path.suffix.lower().lstrip(".")
        name = self.evidence_path.name.lower()

        # Extension-based detection
        disk_exts = {"e01", "dd", "raw", "img", "iso", "aff", "vmdk", "vhd", "ewf"}
        if ext in disk_exts:
            return "disk_image" if ext not in {"e01", "iso"} else ext

        # Magic bytes detection
        try:
            with open(self.evidence_path, "rb") as f:
                header = f.read(512)

            # E01 / EWF
            if header[:3] == b"EVF":
                return "e01"
            # ISO 9660
            if header[1:6] == b"CD001":
                return "iso"
            # MBR signature (disk image)
            if header[510:512] == b"\x55\xaa":
                return "disk_image"
            # GPT signature
            if header[512:520] == b"EFI PART" if len(header) > 520 else False:
                return "disk_image"

        except Exception:
            pass

        # Document / logical file types
        doc_exts = {"pdf", "docx", "xlsx", "pptx", "txt", "csv", "json", "xml",
                    "jpg", "jpeg", "png", "gif", "mp4", "avi", "mov", "mp3"}
        if ext in doc_exts:
            return "logical_file"

        return "logical_file"

    def compute_hashes(self) -> Dict[str, str]:
        """
        Compute MD5 and SHA256 hashes of the evidence file.
        Uses chunked reading to handle large files.
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()

        file_size = os.path.getsize(str(self.evidence_path))
        bytes_read = 0

        with open(self.evidence_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
                sha1.update(chunk)
                bytes_read += len(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "file_size": file_size,
            "file_size_human": self._human_size(file_size),
            "file_name": self.evidence_path.name,
        }

    def get_file_info(self) -> Dict:
        """Return basic file information."""
        stat = os.stat(str(self.evidence_path))
        return {
            "name": self.evidence_path.name,
            "size": stat.st_size,
            "size_human": self._human_size(stat.st_size),
            "extension": self.evidence_path.suffix.lower(),
            "path": str(self.evidence_path),
        }

    @staticmethod
    def _human_size(size: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
