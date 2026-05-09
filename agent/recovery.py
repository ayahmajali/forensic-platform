"""
recovery.py — Deep file recovery for the forensic agent.

What this module does
---------------------
Given a folder the investigator selected, identify the *block device* that
folder lives on, then attempt to recover deleted files from it using
whichever recovery tool is strongest for the situation:

    1.  PhotoRec  (testdisk suite, https://www.cgsecurity.org/wiki/PhotoRec)
        — signature-based file carving. Filesystem-agnostic. Strictly more
        powerful than TSK's `tsk_recover` because it works on raw blocks
        without needing the filesystem journal/MFT/inode table to be intact.
        It recovers from emptied trash, formatted partitions, and damaged
        volumes. Free. Cross-platform (macOS via brew, Windows portable,
        Linux via apt).

    2.  Sleuth Kit `tsk_recover` (fallback)
        — undeletes files the filesystem still has metadata for (e.g.
        recently-deleted NTFS MFT entries, or ext4 entries before journal
        rotation). Faster than PhotoRec when it works, but useless once
        the filesystem has reclaimed the metadata.

Why we need a deeper tool than the OS Trash
-------------------------------------------
The user reported: "I deleted files from a folder, emptied the Recycle Bin,
and the tool just opened the empty Recycle Bin." Right — once the Recycle
Bin / Trash is emptied, there's nothing left for the OS to enumerate. The
data lives on (briefly) in the disk's free space, but only block-level
recovery can find it. That's PhotoRec's job.

The hard physical limit: TRIM
-----------------------------
On modern SSDs (every Apple Silicon Mac, every recent Windows laptop,
most NVMe drives), the OS issues a TRIM command after delete+empty,
telling the SSD controller to *physically* zero those flash cells.
This typically completes within seconds. After that, no software can
read the bytes — they no longer exist as electrical charge in the cells.
We detect this case and warn the user before bothering to run PhotoRec.

This module is import-safe on any OS even if the underlying tools are
missing — `is_available()` returns False and the GUI surfaces a friendly
install hint instead of crashing.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# A line-callback the GUI passes in so PhotoRec progress streams into the
# activity log instead of vanishing into stdout.
LogFn = Callable[[str], None]


# ─────────────────────────────────────────────────────────────────────────────
# Tool resolution — find PhotoRec / TSK on this machine
# ─────────────────────────────────────────────────────────────────────────────

def _candidate_dirs() -> List[Path]:
    """Mirror tsk_runner._candidate_dirs() so vendor binaries are found in
    the same priority order: PyInstaller bundle → ./vendor → next-to-exe."""
    out: List[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        out.append(Path(meipass) / "testdisk")
    here = Path(__file__).resolve().parent
    out.append(here / "vendor" / "testdisk")
    if getattr(sys, "frozen", False):
        out.append(Path(sys.executable).resolve().parent / "testdisk")
    return out


def find_photorec() -> Optional[str]:
    """Resolve the PhotoRec binary path, or None if PhotoRec isn't installed."""
    is_win = sys.platform.startswith("win")
    candidates = ["photorec_win.exe"] if is_win else ["photorec"]
    # Vendored copy first so we can ship a portable Windows .exe.
    for d in _candidate_dirs():
        for name in candidates:
            p = d / name
            if p.is_file():
                return str(p)
    # Then PATH (Mac: brew install testdisk; Linux: apt install testdisk).
    for name in candidates + ["photorec"]:
        hit = shutil.which(name)
        if hit:
            return hit
    return None


def install_hint() -> str:
    """Human-readable install instructions for the host platform."""
    sysname = platform.system()
    if sysname == "Darwin":
        return ("Install PhotoRec on macOS:\n\n"
                "    brew install testdisk\n\n"
                "(Homebrew: https://brew.sh)")
    if sysname == "Windows":
        return ("Install PhotoRec on Windows:\n\n"
                "  1. Download the portable zip from\n"
                "     https://www.cgsecurity.org/wiki/TestDisk_Download\n"
                "  2. Unzip it.\n"
                "  3. Copy photorec_win.exe (and the bundled DLLs) into\n"
                "     agent\\vendor\\testdisk\\\n"
                "  4. Re-launch the agent.")
    if sysname == "Linux":
        return ("Install PhotoRec on Linux:\n\n"
                "    sudo apt install testdisk          # Debian / Ubuntu\n"
                "    sudo dnf install testdisk          # Fedora\n"
                "    sudo pacman -S testdisk            # Arch")
    return "Install the testdisk package for your OS to enable deep recovery."


def is_available() -> bool:
    return find_photorec() is not None


# ─────────────────────────────────────────────────────────────────────────────
# Device detection — which block device backs the selected folder?
# ─────────────────────────────────────────────────────────────────────────────

def device_for_path(path: Path) -> Optional[str]:
    """
    Return the raw block device that backs ``path``. Examples:
        /Users/admin/Documents  →  /dev/disk3s5            (macOS)
        C:\\Users\\admin\\Docs  →  \\\\.\\PhysicalDrive0   (Windows)
        /home/me/docs           →  /dev/nvme0n1p2          (Linux)

    Returns None if we can't determine the device (treat as "skip recovery").

    Why Windows returns the *physical drive*, not the volume:
        Windows locks any mounted volume against raw block reads to prevent
        live-filesystem corruption. That means PhotoRec cannot open
        ``\\\\.\\C:`` while C: is mounted — it gets ERROR_SHARING_VIOLATION
        and exits 1. The physical-drive form (``\\\\.\\PhysicalDriveN``)
        sidesteps that lock and exposes raw blocks underneath the volume.
        We resolve drive-letter → physical-disk-number via PowerShell's
        Get-Partition cmdlet, which is present on every Windows 10/11
        install (no extra dependencies).
    """
    sysname = platform.system()
    p = str(path)
    try:
        if sysname == "Darwin":
            out = subprocess.check_output(
                ["df", p], text=True, stderr=subprocess.DEVNULL,
            )
            # df output: <Filesystem> <512-blocks> <Used> <Avail> <Capacity> <iused> <ifree> <%iused> <Mounted on>
            lines = [l for l in out.strip().splitlines() if l.strip()]
            if len(lines) >= 2:
                return lines[-1].split()[0]
        elif sysname == "Linux":
            out = subprocess.check_output(
                ["findmnt", "-no", "SOURCE", "--target", p],
                text=True, stderr=subprocess.DEVNULL,
            )
            return out.strip() or None
        elif sysname == "Windows":
            drive = Path(p).resolve().drive  # "C:"
            if not drive:
                return None
            letter = drive.rstrip(":")
            # Map drive letter → physical disk number via PowerShell.
            # CREATE_NO_WINDOW keeps the briefly-spawned PS console hidden
            # so we don't flash a black box at the investigator.
            try:
                ps_cmd = (
                    f"$ErrorActionPreference='Stop'; "
                    f"(Get-Partition -DriveLetter {letter} "
                    f"| Select-Object -First 1 -ExpandProperty DiskNumber)"
                )
                ps_out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    text=True, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                disk_no = ps_out.strip()
                if disk_no.isdigit():
                    return f"\\\\.\\PhysicalDrive{disk_no}"
            except (subprocess.SubprocessError, OSError):
                pass
            # Fallback if PowerShell isn't available or the letter doesn't
            # map (network share, mounted ISO, etc.). The volume form
            # rarely works for system drives but at least gives PhotoRec
            # something to chew on for unmounted/external volumes.
            return f"\\\\.\\{drive}"
    except (subprocess.SubprocessError, OSError):
        return None
    return None


# ─────────────────────────────────────────────────────────────────────────────
# TRIM / SSD detection — is recovery even *physically* possible?
# ─────────────────────────────────────────────────────────────────────────────

def trim_status(device: str) -> Dict[str, Any]:
    """
    Inspect the device's filesystem + media type and report whether we
    expect TRIM to have already wiped deleted blocks. Returns:

        {
            "filesystem":   "APFS" | "NTFS" | "ext4" | ...,
            "media":        "ssd" | "hdd" | "unknown",
            "trim_likely":  True | False,
            "explanation":  human-readable string for the GUI,
        }

    "trim_likely=True" means recovery is probably futile because the SSD
    controller has zeroed the blocks — show this to the user and let them
    decide whether to bother running PhotoRec at all.
    """
    sysname = platform.system()
    out: Dict[str, Any] = {
        "filesystem": "unknown",
        "media": "unknown",
        "trim_likely": False,
        "explanation": "",
    }

    try:
        if sysname == "Darwin":
            info = subprocess.check_output(
                ["diskutil", "info", device],
                text=True, stderr=subprocess.DEVNULL,
            )
            if re.search(r"File System Personality:\s*APFS", info):
                out["filesystem"] = "APFS"
            elif re.search(r"File System Personality:\s*HFS", info):
                out["filesystem"] = "HFS+"
            if re.search(r"Solid State:\s*Yes", info):
                out["media"] = "ssd"
            elif re.search(r"Solid State:\s*No", info):
                out["media"] = "hdd"
            # On modern macOS, APFS-on-SSD = TRIM enabled by default.
            if out["filesystem"] == "APFS" and out["media"] == "ssd":
                out["trim_likely"] = True
                out["explanation"] = (
                    "This is an APFS volume on an SSD. macOS issues TRIM "
                    "after every empty-trash, telling the SSD controller "
                    "to physically zero those flash cells within seconds. "
                    "Once that has happened, no software (including "
                    "PhotoRec, Sleuth Kit, R-Studio, or commercial tools) "
                    "can recover the data — the bytes no longer exist. "
                    "Recovery is most likely to succeed if you run this "
                    "tool IMMEDIATELY after deletion, on an HDD, or on a "
                    "non-system APFS volume with TRIM disabled."
                )

        elif sysname == "Windows":
            # Drive letter from "\\.\C:"
            letter = device.rstrip(":").rstrip("\\").split("\\")[-1].rstrip(":")
            # NTFS check
            try:
                fs = subprocess.check_output(
                    ["fsutil", "fsinfo", "volumeinfo", f"{letter}:"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                m = re.search(r"File System Name\s*:\s*(\S+)", fs)
                if m:
                    out["filesystem"] = m.group(1)
            except subprocess.SubprocessError:
                pass
            # SSD check via fsutil behavior query DisableDeleteNotify
            # (0 = TRIM enabled, 1 = disabled, "not currently set" on HDD)
            try:
                trim = subprocess.check_output(
                    ["fsutil", "behavior", "query", "DisableDeleteNotify"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                if re.search(r"NTFS\s*=\s*0", trim):
                    out["media"] = "ssd"
                    out["trim_likely"] = True
                    out["explanation"] = (
                        "This volume sits on an SSD with TRIM enabled. "
                        "Windows tells the SSD to zero blocks shortly "
                        "after Empty Recycle Bin — once that happens, "
                        "the data is unrecoverable. Recovery succeeds "
                        "best on HDDs or immediately after deletion."
                    )
            except subprocess.SubprocessError:
                pass

        elif sysname == "Linux":
            # Lightweight check: is the underlying disk rotational?
            base = re.sub(r"p?\d+$", "", os.path.basename(device))
            rot_path = Path(f"/sys/block/{base}/queue/rotational")
            if rot_path.is_file():
                out["media"] = "hdd" if rot_path.read_text().strip() == "1" else "ssd"
            if out["media"] == "ssd":
                out["trim_likely"] = True
                out["explanation"] = (
                    "Underlying device is an SSD; if the filesystem mounts "
                    "with `discard` (or fstrim runs nightly), deleted "
                    "blocks are zeroed and unrecoverable."
                )
    except Exception:
        # Best-effort detection only; never raise from a status call.
        pass

    return out


# ─────────────────────────────────────────────────────────────────────────────
# PhotoRec invocation
# ─────────────────────────────────────────────────────────────────────────────

# PhotoRec emits one line per recovered file when run in /log mode. The line
# we care about looks like:
#     /Users/admin/Desktop/Recovered/recup_dir.1/f0123456.jpg  (1.2M)
_PHOTOREC_FILE_LINE = re.compile(
    r"^(?P<path>(/|[A-Za-z]:\\)[^\s]+\.\S+)\s*(?:\(.*\))?$",
    re.MULTILINE,
)


def _ensure_outdir(out_root: Path) -> Path:
    """Create a fresh, time-stamped output dir under ``out_root``."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = out_root / f"PhotoRec-{stamp}"
    target.mkdir(parents=True, exist_ok=True)
    return target


def desktop_recovery_root() -> Path:
    """~/Desktop/TheDeletedFiles, the same root tsk_runner uses."""
    desk = Path.home() / "Desktop" / "TheDeletedFiles"
    desk.mkdir(parents=True, exist_ok=True)
    return desk


def needs_admin() -> bool:
    """True unless the current process can already read raw devices."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() == 0  # type: ignore[attr-defined]
        except Exception:
            return True
    # Unix: euid 0 is root; otherwise we'll need sudo.
    return os.geteuid() != 0


def _build_elevated_command(
    binary: str, args: List[str], *, on_log: Optional[LogFn] = None,
) -> List[str]:
    """
    Wrap (binary + args) so it runs with admin/root privileges via the
    native OS prompt — *not* a terminal-only sudo. The investigator sees
    the standard macOS password dialog or Windows UAC dialog.

    macOS:  uses `osascript` → AppleScript "do shell script … with
            administrator privileges". Pops the system Touch ID / password
            prompt. Bypasses Terminal entirely.
    Linux:  uses `pkexec` (PolicyKit) which gives the GNOME / KDE prompt;
            falls back to plain `sudo` for headless boxes.
    Windows: uses `powershell Start-Process -Verb RunAs` which triggers UAC.
            Output is captured via a temp log file because UAC-elevated
            children can't share the parent's stdout pipe.
    """
    sysname = platform.system()
    quoted = ' '.join(_shell_quote(x) for x in [binary, *args])

    if sysname == "Darwin":
        # AppleScript "do shell script" returns the *combined* output.
        script = (
            'do shell script "' + quoted.replace('"', '\\"') +
            ' 2>&1" with administrator privileges'
        )
        if on_log:
            on_log("[admin] requesting macOS password prompt for PhotoRec…")
        return ["osascript", "-e", script]

    if sysname == "Linux":
        if shutil.which("pkexec"):
            if on_log:
                on_log("[admin] requesting PolicyKit prompt for PhotoRec…")
            return ["pkexec", binary, *args]
        if on_log:
            on_log("[admin] no pkexec — falling back to sudo (-A if available)")
        # -A asks the configured askpass helper for a graphical prompt; the
        # plain `sudo` will use the controlling tty otherwise.
        return ["sudo", "-A", binary, *args]

    if sysname == "Windows":
        # Start-Process -Verb RunAs triggers UAC. We redirect output to a
        # temp file because the UAC-elevated child runs in its own console
        # and cannot share the parent's stdout pipe.
        import tempfile
        log_path = tempfile.NamedTemporaryFile(
            delete=False, suffix=".log",
        ).name
        if on_log:
            on_log(f"[admin] requesting UAC for PhotoRec; log → {log_path}")

        # IMPORTANT: PowerShell single-quoted strings are LITERAL — no
        # backslash escaping. That is exactly what we want for Windows
        # paths like "C:\\Users\\admin\\…". Escape embedded single quotes
        # by doubling them, per PS quoting rules.
        arg_list = ", ".join(_ps_quote(a) for a in args)
        ps = (
            f"$out = {_ps_quote(log_path)}; "
            f"$err = {_ps_quote(log_path + '.err')}; "
            f"Start-Process -FilePath {_ps_quote(binary)} "
            f"-ArgumentList @({arg_list}) "
            f"-Verb RunAs -Wait "
            f"-RedirectStandardOutput $out "
            f"-RedirectStandardError $err; "
            f"Get-Content $out, $err -ErrorAction SilentlyContinue"
        )
        return ["powershell", "-NoProfile", "-Command", ps]

    return [binary, *args]  # last-resort: best-effort, no elevation


def _shell_quote(s: str) -> str:
    """Minimal POSIX-ish shell quoting for AppleScript embedding."""
    if not s:
        return "''"
    safe = re.compile(r"^[A-Za-z0-9_\-./:=,]+$")
    if safe.match(s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _ps_quote(s: str) -> str:
    """PowerShell single-quote escaping. Single quotes are doubled; all
    other characters (including backslashes) are kept literal — which is
    exactly what we need for Windows paths."""
    return "'" + s.replace("'", "''") + "'"


def run_photorec(
    *,
    device: str,
    out_dir: Path,
    on_log: Optional[LogFn] = None,
    file_types: Optional[List[str]] = None,
    timeout_seconds: int = 14400,   # 4h — internal NVMe ≈ 1h40m, USB ≈ 10–60m
    elevate: bool = True,
) -> Dict[str, Any]:
    """
    Run PhotoRec non-interactively against ``device``, dropping recovered
    files into ``out_dir``. When ``elevate=True`` (the default) and the
    process isn't already root/admin, the call is wrapped in the native
    OS admin prompt — Touch ID / password on macOS, UAC on Windows,
    PolicyKit on Linux.

    Returns a dict the GUI can render directly:

        {
            "tool":            "photorec",
            "device":          "/dev/disk3s5",
            "output_dir":      "/Users/admin/Desktop/TheDeletedFiles/PhotoRec-…",
            "recovered_count": 42,
            "recovered_files": [{"path": "...", "size": 12345}, ...],
            "log":             "stdout/stderr blob",
            "exit_code":       0 | nonzero,
            "error":           "" | "human explanation",
        }
    """
    binary = find_photorec()
    if not binary:
        return {
            "tool": "photorec",
            "device": device,
            "output_dir": str(out_dir),
            "recovered_count": 0,
            "recovered_files": [],
            "log": "",
            "exit_code": -1,
            "error": "PhotoRec is not installed. " + install_hint(),
        }

    out_prefix = str(out_dir / "recup_dir")
    cmd_arg = "partition_none,fileopt,everything,enable,search"
    # /log enables PhotoRec's own diagnostic log → photorec.log in CWD.
    # We set CWD to out_dir below so the log lands somewhere we control,
    # and read it back after the run for the GUI's "Tool message" panel.
    # Without this, when PhotoRec exits with code 1 we have no idea why,
    # because its error output went to a console buffer that disappeared
    # the moment the child died.
    photorec_args: List[str] = ["/log", "/d", out_prefix, "/cmd", device, cmd_arg]

    if elevate and needs_admin():
        cmd = _build_elevated_command(binary, photorec_args, on_log=on_log)
    else:
        cmd = [binary, *photorec_args]

    if on_log:
        on_log(f"$ {' '.join(_shell_quote(x) for x in cmd)}")

    # Windows-specific subprocess setup. PhotoRec uses Win32 console
    # APIs for its TUI (the "Stop" button you see in a manual run is a
    # console UI element), so it needs a real console window — not just
    # a console *handle*. CREATE_NO_WINDOW allocates a handle but no
    # window, which makes PhotoRec call GetConsoleScreenBufferInfo()
    # against an invalid buffer and exit 1 immediately. CREATE_NEW_CONSOLE
    # gives the child its own real console; PhotoRec then initializes
    # cleanly. The cost is a visible console window for the duration of
    # the scan, which for a forensics demo is arguably useful — the
    # operator can watch PhotoRec's live carving progress.
    #
    # stdout is still piped because PhotoRec's banner + summary lines
    # are plain printf, captured independently of the console buffer.
    # The ncurses-style status line goes to the console window only.
    popen_kwargs: Dict[str, Any] = {
        "stdin":  subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text":   True,
        "bufsize": 1,
        # cwd is set to out_dir so PhotoRec's /log file (photorec.log)
        # lands somewhere we can read back, instead of polluting the
        # agent's working directory (or _MEIPASS, which is read-only).
        "cwd":    str(out_dir),
    }
    if platform.system() == "Windows":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010)
        )
        # PhotoRec's bundled ncurses (PDCurses) needs to find a terminfo
        # entry for whichever terminal type it thinks it's running under.
        # The Windows TestDisk distribution ships `63/cygwin` next to the
        # binary; without it, PhotoRec exits with "Terminfo file is
        # missing." Tell ncurses to look in the binary's own directory
        # (in a frozen bundle that's _MEIPASS\testdisk\, where the build
        # script has placed `63/cygwin` via --add-data).
        env = os.environ.copy()
        env["TERMINFO"] = os.path.dirname(os.path.abspath(binary))
        # Belt-and-suspenders: also point TERM at "cygwin" so PDCurses
        # picks the entry we shipped, rather than probing for $TERM (which
        # on Windows is often unset → ncurses falls back to "unknown").
        env.setdefault("TERM", "cygwin")
        popen_kwargs["env"] = env

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except FileNotFoundError as e:
        return {
            "tool": "photorec",
            "device": device,
            "output_dir": str(out_dir),
            "recovered_count": 0,
            "recovered_files": [],
            "log": "",
            "exit_code": -1,
            "error": f"Could not launch PhotoRec: {e}",
        }

    log_lines: List[str] = []
    try:
        if proc.stdout is not None:
            for line in proc.stdout:
                line = line.rstrip()
                log_lines.append(line)
                if on_log:
                    on_log(line)
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return {
            "tool": "photorec",
            "device": device,
            "output_dir": str(out_dir),
            "recovered_count": 0,
            "recovered_files": [],
            "log": "\n".join(log_lines),
            "exit_code": -1,
            "error": (f"PhotoRec exceeded the {timeout_seconds}s timeout. "
                      "Re-run from a terminal with a longer budget if the "
                      "device is large."),
        }

    # Read PhotoRec's own diagnostic log (created by the /log flag).
    # This is the only way to see WHY PhotoRec exited 1 on Windows —
    # its console buffer is gone the moment the child dies.
    photorec_log_text = ""
    photorec_log_path = out_dir / "photorec.log"
    if photorec_log_path.is_file():
        try:
            photorec_log_text = photorec_log_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            pass
        if on_log and photorec_log_text:
            on_log("--- photorec.log ---")
            for ln in photorec_log_text.splitlines()[-80:]:
                on_log(ln)
            on_log("--- end photorec.log ---")

    # Walk the output prefix.* directories to enumerate what landed.
    recovered: List[Dict[str, Any]] = []
    parent = out_dir
    if parent.is_dir():
        for sub in parent.iterdir():
            if not sub.is_dir() or not sub.name.startswith("recup_dir"):
                continue
            for f in sub.rglob("*"):
                if f.is_file():
                    try:
                        recovered.append({
                            "path": str(f),
                            "name": f.name,
                            "size": f.stat().st_size,
                        })
                    except OSError:
                        continue

    error_msg = ""
    if proc.returncode != 0 and not recovered:
        sysname = platform.system()
        if sysname == "Windows":
            error_msg = (
                f"PhotoRec exited with code {proc.returncode} on "
                f"{device}.\n\n"
                "Most common causes on Windows:\n"
                "  • UAC was declined or the agent is not running as "
                "administrator (right-click the .exe → Run as "
                "administrator).\n"
                "  • The selected drive is busy / in use by another "
                "process. Close any open files on it and retry.\n"
                "  • The drive is encrypted with BitLocker — PhotoRec "
                "cannot read raw blocks through BitLocker. Suspend "
                "BitLocker for the drive and retry."
            )
        else:
            error_msg = (
                f"PhotoRec exited with code {proc.returncode}. "
                f"On Unix this usually means the process needs root — "
                f"re-launch the agent with `sudo`."
            )

        # If PhotoRec wrote its own diagnostic log, show the tail to the
        # user — that's where the actual root cause (e.g. "fopen failed
        # for \\.\PhysicalDrive0", "no partition found", etc.) is going
        # to be. Tail only because the full file can be megabytes.
        if photorec_log_text.strip():
            tail = "\n".join(photorec_log_text.splitlines()[-25:])
            error_msg += (
                "\n\nPhotoRec's own log (tail, full copy at "
                f"{photorec_log_path}):\n"
                "────────────────────────────────────────\n"
                f"{tail}"
            )

    # Combine our captured stdout/stderr with PhotoRec's own log file
    # so the GUI's Deep Recovery tab gets one consolidated text blob.
    combined_log = "\n".join(log_lines[-200:])
    if photorec_log_text:
        combined_log = (
            combined_log
            + "\n\n=== PhotoRec internal log (photorec.log) ===\n"
            + photorec_log_text
        )

    return {
        "tool": "photorec",
        "device": device,
        "output_dir": str(out_dir),
        "recovered_count": len(recovered),
        "recovered_files": recovered,
        "log": combined_log,
        "exit_code": proc.returncode,
        "error": error_msg,
        "photorec_log_path": str(photorec_log_path),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Top-level convenience: recover everything we can from a folder's device
# ─────────────────────────────────────────────────────────────────────────────

def recover_for_folder(
    folder: Path,
    *,
    on_log: Optional[LogFn] = None,
    elevate: bool = True,
) -> Dict[str, Any]:
    """
    The high-level entry point the GUI actually calls. Given a selected
    folder, identify the device, check TRIM, and run PhotoRec into
    ``~/Desktop/TheDeletedFiles/PhotoRec-<timestamp>/``.

    When ``elevate=True`` (the default) and the agent isn't already root /
    administrator, PhotoRec is wrapped in the *native OS admin prompt* —
    Touch ID / password dialog on macOS, UAC on Windows, PolicyKit on
    Linux. The investigator does NOT have to relaunch the app from a
    terminal with ``sudo``.

    The returned dict is shaped so the GUI can render it without any
    additional translation — it always includes ``status``, which is one of:

        "ok"               — recovery completed (files may be 0 if disk is
                             genuinely empty, or TRIM has wiped everything)
        "skipped_trim"     — caller asked us to skip because TRIM almost
                             certainly zeroed the data
        "needs_admin"      — caller passed elevate=False AND the process
                             isn't elevated (legacy code path)
        "no_tool"          — PhotoRec isn't installed; show install hint
        "no_device"        — couldn't resolve the device backing the folder
        "error"            — anything else; see ``error`` for details
    """
    folder = Path(folder).resolve()
    log = on_log or (lambda _l: None)

    if not is_available():
        return {
            "status": "no_tool",
            "tool": "photorec",
            "device": None,
            "trim": None,
            "output_dir": None,
            "recovered_count": 0,
            "recovered_files": [],
            "error": install_hint(),
        }

    device = device_for_path(folder)
    if not device:
        return {
            "status": "no_device",
            "tool": "photorec",
            "device": None,
            "trim": None,
            "output_dir": None,
            "recovered_count": 0,
            "recovered_files": [],
            "error": ("Could not determine which disk backs "
                      f"'{folder}'. Try a folder on a local drive."),
        }

    log(f"Selected folder lives on device: {device}")
    trim = trim_status(device)
    if trim.get("explanation"):
        log("[!] " + trim["explanation"])

    # Only short-circuit if the caller has *explicitly* opted out of
    # native elevation — otherwise let run_photorec() pop the OS prompt.
    if not elevate and needs_admin():
        return {
            "status": "needs_admin",
            "tool": "photorec",
            "device": device,
            "trim": trim,
            "output_dir": None,
            "recovered_count": 0,
            "recovered_files": [],
            "error": (
                "Deep recovery needs to read the raw block device "
                f"({device}), which requires elevated privileges.\n\n"
                "macOS / Linux:  re-launch the agent like this →\n"
                "    sudo python forensic_agent_gui.py\n\n"
                "Windows:  right-click ForensicAgent.exe → Run as "
                "administrator."
            ),
        }

    if elevate and needs_admin():
        log("[admin] PhotoRec needs raw-device access — you'll see the "
            "system password prompt next.")

    out_dir = _ensure_outdir(desktop_recovery_root() / folder.name)
    log(f"Recovering into: {out_dir}")
    result = run_photorec(
        device=device, out_dir=out_dir, on_log=log, elevate=elevate,
    )
    result["status"] = "ok" if not result.get("error") else "error"
    result["trim"] = trim
    result["folder"] = str(folder)
    return result
