"""
tsk_runner.py — Local Sleuth Kit runner for the Windows forensic agent.

The agent can analyse a disk image (.dd, .e01, .raw, .img, .iso) *on the
user's own machine* and extract deleted / unallocated files to the Desktop,
without needing to upload the image to the Render backend.

This module wraps the TSK CLI tools (mmls, fsstat, fls, tsk_recover) and
parses their stdout into a structured dict that matches the shape the
backend's `modules/disk_analysis.py` produces — so the findings JSON we ship
to the backend can reuse the same `/case/{id}` renderer.

TSK binary resolution order
---------------------------
1. ``sys._MEIPASS/tsk/``         — where PyInstaller extracts bundled binaries
                                    at runtime when we ship a one-file .exe.
2. ``<agent_dir>/vendor/tsk/``   — for `python forensic_agent_gui.py` runs
                                    before the .exe is built.
3. ``$PATH``                     — if the user installed TSK globally.

If TSK isn't found in any of those places, ``LocalTSKRunner.is_available``
returns False and the GUI surfaces a friendly install prompt instead of
crashing.

Deleted file recovery
---------------------
``LocalTSKRunner.analyse`` drops recovered bytes into a caller-provided
output directory. The GUI's convenience helper
``recover_deleted_to_desktop(image)`` uses ``~/Desktop/TheDeletedFiles/``.
Every deleted file is paired with its inode and original path so the
investigator can see exactly what came out of the image.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# Subset of TSK tools the agent uses. `icat` is included for future
# per-inode extraction; `mactime` is not needed here (the backend builds
# the timeline from browser history + file mtimes, not TSK body files).
TSK_BINARIES = ("mmls", "fsstat", "fls", "tsk_recover", "icat")

# On Windows the binaries are ``mmls.exe`` etc.; on macOS/Linux they're
# bare names. ``shutil.which`` handles both transparently but we need the
# right filename when searching ``vendor/tsk/`` manually.
_IS_WINDOWS = sys.platform.startswith("win")


# ────────────────────────────────────────────────────────────────────────────
# Binary resolution
# ────────────────────────────────────────────────────────────────────────────

def _candidate_dirs() -> List[Path]:
    """Return directories to search for bundled TSK binaries, in priority order."""
    dirs: List[Path] = []

    # 1. PyInstaller one-file extraction dir (sys._MEIPASS is set at runtime).
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass) / "tsk")

    # 2. Dev-mode: alongside the agent source.
    here = Path(__file__).resolve().parent
    dirs.append(here / "vendor" / "tsk")

    # 3. A sibling "tsk" folder next to the .exe (optional "drop-in" install).
    if getattr(sys, "frozen", False):
        dirs.append(Path(sys.executable).resolve().parent / "tsk")

    return dirs


def _binary_filename(name: str) -> str:
    return f"{name}.exe" if _IS_WINDOWS else name


def resolve_tsk_binary(name: str) -> Optional[str]:
    """Return the absolute path to a TSK binary, or None if not found."""
    fname = _binary_filename(name)
    for d in _candidate_dirs():
        candidate = d / fname
        if candidate.is_file():
            return str(candidate)

    # Finally, fall back to anything on PATH.
    hit = shutil.which(name) or shutil.which(fname)
    return hit


# ────────────────────────────────────────────────────────────────────────────
# Output parsers
# ────────────────────────────────────────────────────────────────────────────

_FLS_RE = re.compile(
    r"""^\s*
        (?P<type>[bcdflrsh\-])          # entry type from TSK (r=regular, d=dir, …)
        /
        (?P<alloc>[bcdflrsh\-])         # allocated-type
        \s+
        (?P<star>\*?)                   # '*' marks deleted
        \s*
        (?P<inode>[\d\-]+(?::[\d\-]+)*) # inode or inode-type-id triple
        [:\s]+
        (?P<name>.+?)\s*$
    """,
    re.VERBOSE,
)


def _parse_mmls(output: str) -> List[Dict[str, Any]]:
    """Parse ``mmls`` output into a list of partitions."""
    parts: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.rstrip()
        # Skip headers / empty lines
        if not line or line.startswith(("DOS", "GPT", "Units", "Slot", "Offset")):
            continue
        tokens = line.split(None, 4)
        if len(tokens) < 5:
            continue
        try:
            slot, start, end, length, desc = tokens
            parts.append({
                "slot": slot.rstrip(":"),
                "start": int(start),
                "end": int(end),
                "length": int(length),
                "description": desc.strip(),
                "offset_bytes": int(start) * 512,
            })
        except ValueError:
            continue
    return parts


def _pick_primary_offset(partitions: List[Dict[str, Any]]) -> int:
    """Guess the most useful partition start offset in sectors.

    Skips unallocated / extended / metadata partitions — we want the first
    real filesystem so ``fls`` and ``tsk_recover`` return useful data.
    """
    for p in partitions:
        desc = str(p.get("description", "")).lower()
        if any(x in desc for x in ("unalloc", "extended", "meta", "empty")):
            continue
        if p.get("start", 0) > 0:
            return int(p["start"])
    for p in partitions:
        if p.get("start", 0) > 0:
            return int(p["start"])
    return 0


def _parse_fsstat(output: str) -> Dict[str, Any]:
    """Extract a handful of useful fields from ``fsstat`` output."""
    info: Dict[str, Any] = {
        "fs_type": "unknown",
        "volume_name": "",
        "last_mount": "",
        "block_size": "",
        "block_count": "",
    }
    for raw in output.splitlines():
        line = raw.strip()
        low = line.lower()
        if "file system type:" in low:
            info["fs_type"] = line.split(":", 1)[1].strip()
        elif low.startswith("volume name:"):
            info["volume_name"] = line.split(":", 1)[1].strip()
        elif "last mount" in low and ":" in line:
            info["last_mount"] = line.split(":", 1)[1].strip()
        elif low.startswith("block size:"):
            info["block_size"] = line.split(":", 1)[1].strip()
        elif low.startswith(("block count:", "block range:")):
            info["block_count"] = line.split(":", 1)[1].strip()
    return info


def _parse_fls(output: str) -> List[Dict[str, Any]]:
    """Parse ``fls -rd`` output into structured deleted-file records.

    TSK's ``fls -rd`` emits lines like::

        r/r * 1234-128-1:\tUsers/Jane/Desktop/secret.txt
        d/d 56:\tSystem Volume Information

    Only rows whose allocation marker is ``-`` (the second slash group) OR
    prefixed with ``*`` are deleted. We also surface the inode triple so
    ``icat`` can be pointed at individual entries if the user wants.
    """
    entries: List[Dict[str, Any]] = []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        m = _FLS_RE.match(raw)
        if not m:
            continue
        is_deleted = m.group("alloc") == "-" or bool(m.group("star"))
        entry_type = "directory" if m.group("type") == "d" else "file"
        entries.append({
            "type": entry_type,
            "inode": m.group("inode"),
            "name": m.group("name").strip(),
            "deleted": is_deleted,
        })
    return entries


# ────────────────────────────────────────────────────────────────────────────
# LocalTSKRunner
# ────────────────────────────────────────────────────────────────────────────


class LocalTSKRunner:
    """Runs The Sleuth Kit on a disk image locally (Windows / macOS / Linux).

    Usage::

        runner = LocalTSKRunner(Path("C:/evidence/test.dd"))
        if not runner.is_available:
            print(runner.why_missing())
            return
        result = runner.analyse(
            output_dir=Path.home() / "Desktop" / "TheDeletedFiles",
            on_log=print,
        )
        print(result["summary"])
        for d in result["deleted_files"]:
            print(d["inode"], d["name"])
    """

    def __init__(self, image_path: Path) -> None:
        self.image_path = Path(image_path).resolve()
        # Resolve each binary exactly once so we can present a clear
        # "missing tool" diagnostic if something isn't vendored in.
        self._bin: Dict[str, Optional[str]] = {
            name: resolve_tsk_binary(name) for name in TSK_BINARIES
        }

    # ── diagnostics ─────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """True when the minimum required tools (mmls, fls, tsk_recover) exist."""
        return all(self._bin.get(n) for n in ("mmls", "fls", "tsk_recover"))

    def why_missing(self) -> str:
        """Human-readable reason ``is_available`` is False. Empty when all good."""
        missing = [n for n in ("mmls", "fls", "tsk_recover") if not self._bin.get(n)]
        if not missing:
            return ""
        return (
            f"Missing Sleuth Kit tool(s): {', '.join(missing)}. "
            "Install TSK from https://www.sleuthkit.org/sleuthkit/download.php "
            "and place the .exe files in the agent's vendor/tsk/ folder, "
            "or add them to PATH."
        )

    def tool_versions(self) -> Dict[str, Optional[str]]:
        """Best-effort version string per resolved TSK binary (for /health-style views)."""
        out: Dict[str, Optional[str]] = {}
        for name, path in self._bin.items():
            if not path:
                out[name] = None
                continue
            try:
                r = subprocess.run(
                    [path, "-V"], capture_output=True, text=True, timeout=8
                )
                out[name] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "unknown"
            except Exception as e:
                out[name] = f"error: {e}"
        return out

    # ── low-level exec wrapper ─────────────────────────────────────────

    def _run(self, tool: str, args: List[str], *, timeout: int = 300) -> Tuple[str, str, int]:
        path = self._bin.get(tool)
        if not path:
            return "", f"{tool} not available", 127

        # Suppress the Windows console window for bundled .exe runs.
        startupinfo = None
        creationflags = 0
        if _IS_WINDOWS:
            startupinfo = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        try:
            proc = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            return proc.stdout or "", proc.stderr or "", proc.returncode
        except subprocess.TimeoutExpired:
            return "", f"{tool} timed out after {timeout}s", -1
        except OSError as e:
            return "", f"{tool} failed to start: {e}", -1

    # ── high-level analysis ────────────────────────────────────────────

    def analyse(
        self,
        output_dir: Path,
        *,
        on_log: Optional[Callable[[str], None]] = None,
        deleted_only: bool = True,
    ) -> Dict[str, Any]:
        """Run the full TSK pipeline and recover deleted files.

        Parameters
        ----------
        output_dir
            Where ``tsk_recover`` should drop recovered files. Created if
            it doesn't exist.
        on_log
            Callable receiving one-line status updates, for the GUI to
            display live. Safe to pass ``None``.
        deleted_only
            When True, invoke ``tsk_recover -e`` so *only* unallocated /
            deleted files are extracted (the common case). When False,
            extract every file the filesystem can see.
        """
        log = on_log or (lambda _msg: None)

        if not self.image_path.exists():
            return {"error": f"Image not found: {self.image_path}",
                    "tsk_available": self.is_available}

        if not self.is_available:
            return {"error": self.why_missing(),
                    "tsk_available": False}

        output_dir = Path(output_dir).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        result: Dict[str, Any] = {
            "tsk_available": True,
            "image_path": str(self.image_path),
            "output_dir": str(output_dir),
            "tool_versions": self.tool_versions(),
        }

        # 1. mmls — partition table
        log("Running mmls (partition discovery)…")
        mmls_out, mmls_err, _ = self._run("mmls", [str(self.image_path)], timeout=60)
        partitions = _parse_mmls(mmls_out)
        result["partitions"] = partitions
        result["mmls_raw"] = mmls_out or mmls_err

        offset = _pick_primary_offset(partitions)
        result["offset"] = offset
        if partitions:
            log(f"  → {len(partitions)} partition(s); using offset {offset}")
        else:
            log("  → no partition table; treating as a flat filesystem")

        # 2. fsstat — filesystem info
        log("Running fsstat (filesystem metadata)…")
        fsstat_args: List[str] = []
        if offset > 0:
            fsstat_args += ["-o", str(offset)]
        fsstat_args.append(str(self.image_path))
        fsstat_out, fsstat_err, _ = self._run("fsstat", fsstat_args, timeout=90)
        result["fsstat"] = _parse_fsstat(fsstat_out)
        result["fsstat_raw"] = fsstat_out or fsstat_err
        log(f"  → fs_type={result['fsstat'].get('fs_type', 'unknown')}")

        # 3. fls -rd — listing deleted files (with paths!)
        log("Running fls -rd (deleted-file index)…")
        fls_args = ["-rd"]
        if offset > 0:
            fls_args += ["-o", str(offset)]
        fls_args.append(str(self.image_path))
        fls_out, fls_err, _ = self._run("fls", fls_args, timeout=240)
        deleted_entries = [e for e in _parse_fls(fls_out) if e["deleted"]]
        result["deleted_files"] = deleted_entries
        result["total_deleted"] = len(deleted_entries)
        log(f"  → {len(deleted_entries)} deleted file record(s) found")

        # 4. tsk_recover — pull the bytes out
        # ``-e`` restricts recovery to deleted/unallocated entries.
        # Without it we'd recover every file on the filesystem, which is
        # rarely what the investigator asked for on a "deleted files"
        # workflow and can fill the disk quickly.
        log(f"Running tsk_recover → {output_dir}")
        recover_args: List[str] = []
        if deleted_only:
            recover_args.append("-e")
        if offset > 0:
            recover_args += ["-o", str(offset)]
        recover_args += [str(self.image_path), str(output_dir)]
        rec_out, rec_err, rec_rc = self._run("tsk_recover", recover_args, timeout=900)
        result["tsk_recover_raw"] = (rec_out + "\n" + rec_err).strip()
        result["tsk_recover_returncode"] = rec_rc

        # 5. Walk the output folder to tally what was actually recovered.
        recovered_paths: List[Dict[str, Any]] = []
        for root, _dirs, files in os.walk(str(output_dir)):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    size = fpath.stat().st_size
                except OSError:
                    size = 0
                try:
                    rel = fpath.relative_to(output_dir)
                except ValueError:
                    rel = fpath
                recovered_paths.append({
                    "name": fname,
                    "relative_path": str(rel).replace("\\", "/"),
                    "absolute_path": str(fpath),
                    "size": size,
                })

        result["recovered_files"] = recovered_paths
        result["recovered_count"] = len(recovered_paths)
        log(f"  → extracted {len(recovered_paths)} file(s) to {output_dir}")

        # Summary block the GUI can show verbatim.
        result["summary"] = {
            "image": self.image_path.name,
            "partitions": len(partitions),
            "fs_type": result["fsstat"].get("fs_type", "unknown"),
            "deleted_total": len(deleted_entries),
            "recovered_total": len(recovered_paths),
            "output_dir": str(output_dir),
        }
        return result


# ────────────────────────────────────────────────────────────────────────────
# Convenience API — Desktop drop-off
# ────────────────────────────────────────────────────────────────────────────

def desktop_deleted_files_dir() -> Path:
    """Return (and create) ``~/Desktop/TheDeletedFiles/``.

    Handles the Windows quirk where Desktop may be redirected to OneDrive
    or localized (e.g. ``Escritorio``). We try:
        1. ``USERPROFILE/Desktop``           (Windows default)
        2. ``USERPROFILE/OneDrive/Desktop``  (OneDrive backup enabled)
        3. ``Path.home()/Desktop``           (macOS / Linux default)
    The first path whose parent already exists is chosen. We then create
    the ``TheDeletedFiles`` subfolder inside it.
    """
    candidates: List[Path] = []
    if _IS_WINDOWS:
        user = os.environ.get("USERPROFILE") or str(Path.home())
        candidates.append(Path(user) / "Desktop")
        candidates.append(Path(user) / "OneDrive" / "Desktop")
    candidates.append(Path.home() / "Desktop")

    desktop = next((c for c in candidates if c.parent.exists()), candidates[0])
    target = desktop / "TheDeletedFiles"
    target.mkdir(parents=True, exist_ok=True)
    return target


def recover_deleted_to_desktop(
    image_path: Path,
    *,
    on_log: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """One-call helper: analyse image, drop deleted files on the Desktop."""
    runner = LocalTSKRunner(image_path)
    if not runner.is_available:
        return {"error": runner.why_missing(), "tsk_available": False}
    return runner.analyse(desktop_deleted_files_dir(), on_log=on_log)


# ────────────────────────────────────────────────────────────────────────────
# CLI entry-point (useful for debugging without the GUI)
# ────────────────────────────────────────────────────────────────────────────

def _cli() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="tsk_runner",
        description="Analyse a disk image locally and recover deleted files to the Desktop.",
    )
    parser.add_argument("image", type=Path, help="Path to .dd / .e01 / .raw / .img / .iso")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to drop recovered files (default: ~/Desktop/TheDeletedFiles)",
    )
    parser.add_argument(
        "--include-allocated",
        action="store_true",
        help="Recover all files, not just deleted/unallocated ones.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the full result as JSON on stdout.")
    args = parser.parse_args()

    output_dir = args.output or desktop_deleted_files_dir()
    runner = LocalTSKRunner(args.image)
    if not runner.is_available:
        print(runner.why_missing(), file=sys.stderr)
        return 2

    result = runner.analyse(
        output_dir,
        on_log=lambda m: print(m),
        deleted_only=not args.include_allocated,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        s = result.get("summary", {})
        print("")
        print(f"  Image      : {s.get('image')}")
        print(f"  Partitions : {s.get('partitions')}")
        print(f"  FS type    : {s.get('fs_type')}")
        print(f"  Deleted    : {s.get('deleted_total')} record(s)")
        print(f"  Recovered  : {s.get('recovered_total')} file(s)")
        print(f"  Drop dir   : {s.get('output_dir')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
