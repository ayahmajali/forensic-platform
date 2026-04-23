"""
gui.py — Forensic Agent desktop GUI.

A native CustomTkinter app that lets an investigator point at a folder
of evidence and get back a complete forensic picture:

    • Inventory every file with MD5 / SHA-256 hashes.
    • Pull EXIF, document text, video metadata, browser history
      (the last one opt-in for privacy).
    • Auto-detect disk images (.dd / .e01 / .raw / .img / .iso / .vmdk)
      nested inside the evidence folder and run the full Sleuth Kit
      pipeline on each of them locally — mmls → fsstat → fls → tsk_recover.
    • Recover any deleted files to Desktop\\TheDeletedFiles\\<image>\\.
    • Surface a "recently modified" view with MAC timestamps so the
      investigator can spot what moved on the suspect machine.
    • Ship the structured findings JSON to the backend for reporting.

Design notes
------------
* All work happens in a background `threading.Thread`; Tk widgets are
  only ever touched on the main thread via a `queue.Queue` drained
  every 50 ms.
* Scanner + TSK modules are imported lazily, so the GUI can still
  launch and show a friendly error on a broken install.
* We use `ctk.CTkTabview` for the results area so "Overview / Modified
  Files / Deleted Files / Errors" are separate panes instead of one
  long scroll.

Entry point: `main()` — called by forensic_agent_gui.py.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        f"Missing GUI dependency: {e}\n"
        "Install with: pip install customtkinter\n"
    )
    sys.exit(1)

try:
    import requests
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        f"Missing HTTP dependency: {e}\n"
        "Install with: pip install requests\n"
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

APP_TITLE = "Forensic Agent"
APP_VERSION = "1.2.0"
DEFAULT_BACKEND = os.getenv("FORENSIC_API_URL", "https://forensic-platform-sy5q.onrender.com")
DEFAULT_API_KEY = os.getenv("FORENSIC_API_KEY", "")

# Disk-image file extensions — when the scanner discovers any of these
# inside the evidence folder, the agent automatically runs TSK on them.
DISK_IMAGE_EXTS = {".dd", ".raw", ".img", ".iso", ".e01", ".vmdk"}

# Default "recently modified" window in days. Files touched inside this
# window surface on the Modified tab first.
DEFAULT_MODIFIED_WINDOW_DAYS = 30

# ── Palette ──────────────────────────────────────────────────────────
# Refined "premium" dark palette: deep midnight with cool surfaces, a
# softer indigo accent (Tailwind indigo-400) that pops against the
# background without being harsh on projector screens, and clearer
# semantic colours for warning / danger / success.
CLR_BG          = "#0b1120"   # window background (deep midnight)
CLR_SURFACE     = "#121a2e"   # sidebar, top-bar, primary cards
CLR_SURFACE_2   = "#172041"   # sub-cards inside cards
CLR_ELEVATED    = "#1d2748"   # input backgrounds, chips
CLR_DIVIDER     = "#2a3560"   # hairlines / borders
CLR_ACCENT      = "#818cf8"   # primary indigo accent
CLR_ACCENT_H    = "#6366f1"   # accent hover (deeper)
CLR_ACCENT_SOFT = "#1f2554"   # faint accent wash for badges
CLR_SUCCESS     = "#34d399"   # emerald-400
CLR_WARN        = "#fbbf24"   # amber-400
CLR_DANGER      = "#f87171"   # red-400
CLR_INFO        = "#60a5fa"   # sky/blue-400
CLR_TEXT        = "#f1f5f9"   # slate-100
CLR_TEXT_DIM    = "#cbd5e1"   # slate-300
CLR_MUTED       = "#94a3b8"   # slate-400
CLR_FAINT       = "#64748b"   # slate-500


# ─────────────────────────────────────────────────────────────────────────────
# Lazy module loaders
# ─────────────────────────────────────────────────────────────────────────────

def _load_scanner():
    """Import scanner.py, whether we're installed as a package, run from source,
    or extracted by PyInstaller into sys._MEIPASS."""
    last_exc = None
    for modname in ("scanner", "agent.scanner"):
        try:
            return __import__(modname, fromlist=["*"])
        except ImportError as e:
            last_exc = e
    raise RuntimeError(f"Could not import scanner module: {last_exc}")


def _load_tsk_runner():
    """Same fallback pattern, for agent/tsk_runner.py."""
    last_exc = None
    for modname in ("tsk_runner", "agent.tsk_runner"):
        try:
            return __import__(modname, fromlist=["*"])
        except ImportError as e:
            last_exc = e
    raise RuntimeError(f"Could not import tsk_runner module: {last_exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_size(nbytes: Optional[int]) -> str:
    """1234567 -> '1.2 MB'. Handles None / 0 / negative gracefully."""
    if not nbytes or nbytes < 0:
        return "0 B"
    n = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_ts(iso: Optional[str]) -> str:
    """ISO-UTC -> 'YYYY-MM-DD HH:MM' in the user's local timezone."""
    if not iso:
        return "—"
    try:
        dt = datetime.strptime(iso.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return iso


def _short_path(path: str, limit: int = 72) -> str:
    """Truncate a path in the middle so the filename stays visible."""
    if len(path) <= limit:
        return path
    head = path[: limit // 2 - 2]
    tail = path[-(limit // 2 - 1):]
    return f"{head}…{tail}"


def _open_in_file_manager(target: str) -> None:
    """Open a folder or file in the platform's native file manager."""
    try:
        if platform.system() == "Windows":
            os.startfile(target)  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
    except Exception as e:
        messagebox.showerror(APP_TITLE, f"Could not open:\n{target}\n\n{e}")


# ─────────────────────────────────────────────────────────────────────────────
# System Trash / Recycle Bin scanning
# ─────────────────────────────────────────────────────────────────────────────
#
# In addition to recovering files from disk images via Sleuth Kit, we look at
# the OS-level trash so investigators can see (and recover) files the user
# deleted through normal "Move to Trash" workflows. This is non-destructive —
# we only enumerate, we never delete or empty the trash.
#
#   • Windows: C:\$Recycle.Bin\<SID>\$Rxxxxxx.ext   (carved bytes)
#              C:\$Recycle.Bin\<SID>\$Ixxxxxx.ext   (sidecar with original
#                                                    path + deletion time)
#   • macOS:   ~/.Trash/                            (just files; no metadata)
#   • Linux:   ~/.local/share/Trash/files/           (carved bytes)
#              ~/.local/share/Trash/info/<name>.trashinfo
#
# Each entry returned is a dict shaped like:
#   {
#       "name":           "report.docx",
#       "path":           "C:\\$Recycle.Bin\\S-1-5-21-…\\$Rabc.docx",
#       "original_path":  "C:\\Users\\admin\\Documents\\report.docx",  # may be None
#       "size":           12345,
#       "deleted_at":     "2026-04-21T17:33:21Z",
#       "source":         "Recycle Bin (C:)",
#       "recoverable":    True,
#   }


def _parse_recycle_info_file(info_path: Path) -> Optional[Dict[str, Any]]:
    """
    Parse a Windows ``$I…`` sidecar to extract the original path and deletion
    time. Returns None on any parse error so the caller can fall back to the
    file's mtime / display name.

    File format (Vista–Windows 10+):
        offset 0  (8 bytes)  version (1 = Vista–8, 2 = Win 10+)
        offset 8  (8 bytes)  original size
        offset 16 (8 bytes)  deletion FILETIME (100-ns since 1601-01-01 UTC)
        offset 24 (4 bytes)  name length in chars (Win 10+ only)
        offset 28 (variable) UTF-16-LE original path
    For version 1 the path is fixed-width 520 bytes (260 wchars).
    """
    try:
        import struct
        data = info_path.read_bytes()
        if len(data) < 24:
            return None
        version = struct.unpack("<Q", data[:8])[0]
        ft = struct.unpack("<Q", data[16:24])[0]
        if version >= 2 and len(data) >= 28:
            name_len = struct.unpack("<I", data[24:28])[0]
            raw = data[28:28 + name_len * 2]
        else:
            raw = data[24:24 + 520]
        try:
            secs = (ft - 116444736000000000) / 10_000_000
            deleted_at = datetime.fromtimestamp(secs, tz=timezone.utc)
            deleted_iso = deleted_at.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        except (OverflowError, OSError, ValueError):
            deleted_iso = None
        original_path = raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
        return {
            "original_path": original_path or None,
            "deleted_at": deleted_iso,
        }
    except (OSError, struct.error, ValueError):
        return None


def _scan_macos_trash() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    trash = Path.home() / ".Trash"
    if not trash.is_dir():
        return out
    try:
        for f in trash.iterdir():
            try:
                st = f.stat()
                deleted_at = datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc,
                ).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
                out.append({
                    "name": f.name,
                    "path": str(f),
                    "original_path": None,
                    "size": st.st_size if f.is_file() else 0,
                    "deleted_at": deleted_at,
                    "source": "macOS Trash",
                    "recoverable": True,
                    "is_dir": f.is_dir(),
                })
            except OSError:
                continue
    except OSError:
        pass
    return out


def _scan_windows_recycle_bin() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # Probe every fixed drive letter the user might have. We use os.path.exists
    # because Path("X:\\$Recycle.Bin").is_dir() returns False if the drive
    # letter is unmounted.
    import string
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        recycle_root = Path(drive) / "$Recycle.Bin"
        try:
            if not recycle_root.is_dir():
                continue
        except OSError:
            continue

        try:
            sid_dirs = [p for p in recycle_root.iterdir() if p.is_dir()]
        except (OSError, PermissionError):
            continue

        for sid in sid_dirs:
            try:
                entries = list(sid.iterdir())
            except (OSError, PermissionError):
                continue

            # Build a quick lookup of $I sidecars keyed by their suffix so we
            # can pair each $R<id> with its $I<id> in O(1).
            info_by_suffix: Dict[str, Path] = {}
            for e in entries:
                if e.name.startswith("$I") and len(e.name) > 2:
                    info_by_suffix[e.name[2:]] = e

            for e in entries:
                if not e.name.startswith("$R") or e.name.startswith("$Recycle"):
                    continue
                try:
                    st = e.stat()
                except OSError:
                    continue
                size = st.st_size if e.is_file() else 0

                meta: Dict[str, Any] = {}
                sidecar = info_by_suffix.get(e.name[2:])
                if sidecar:
                    parsed = _parse_recycle_info_file(sidecar)
                    if parsed:
                        meta = parsed

                deleted_at = meta.get("deleted_at") or (
                    datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S") + "Z"
                )
                original = meta.get("original_path")
                display_name = (
                    original.split("\\")[-1] if original else e.name
                )

                out.append({
                    "name": display_name,
                    "path": str(e),
                    "original_path": original,
                    "size": size,
                    "deleted_at": deleted_at,
                    "source": f"Recycle Bin ({letter}:)",
                    "recoverable": True,
                    "is_dir": e.is_dir(),
                })
    return out


def _scan_linux_trash() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    trash_root = Path.home() / ".local" / "share" / "Trash"
    files_dir = trash_root / "files"
    info_dir = trash_root / "info"
    if not files_dir.is_dir():
        return out
    try:
        entries = list(files_dir.iterdir())
    except OSError:
        return out
    for f in entries:
        try:
            st = f.stat()
        except OSError:
            continue
        original = None
        deleted_at = None
        sidecar = info_dir / (f.name + ".trashinfo")
        if sidecar.is_file():
            try:
                for line in sidecar.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines():
                    if line.startswith("Path="):
                        original = line[5:]
                    elif line.startswith("DeletionDate="):
                        deleted_at = line[13:]
            except OSError:
                pass
        if not deleted_at:
            deleted_at = datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        out.append({
            "name": f.name,
            "path": str(f),
            "original_path": original,
            "size": st.st_size if f.is_file() else 0,
            "deleted_at": deleted_at,
            "source": "Linux Trash",
            "recoverable": True,
            "is_dir": f.is_dir(),
        })
    return out


def scan_system_trash() -> List[Dict[str, Any]]:
    """
    Cross-platform trash enumeration. Returns at most ``MAX_TRASH_ENTRIES``
    items so a deeply-cluttered Recycle Bin doesn't blow up the JSON.
    """
    sysname = platform.system()
    try:
        if sysname == "Darwin":
            items = _scan_macos_trash()
        elif sysname == "Windows":
            items = _scan_windows_recycle_bin()
        elif sysname == "Linux":
            items = _scan_linux_trash()
        else:
            items = []
    except Exception:
        # Trash scanning is best-effort; never let it break the main scan.
        items = []
    items.sort(key=lambda x: x.get("deleted_at") or "", reverse=True)
    return items[:MAX_TRASH_ENTRIES]


MAX_TRASH_ENTRIES = 500


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class ForensicAgentApp(ctk.CTk):
    """
    Application window.

    Layout:
        root
        ├─ sidebar      — branding, status, backend config, privacy note
        └─ main          (scrollable)
            ├─ header   — title + one-line description
            ├─ card_evidence  — folder picker + options
            ├─ card_run       — big Start button + progress + live log
            ├─ card_results   — tabbed results (Overview / Modified / Deleted / Errors)
            └─ card_submit    — submit-to-backend + case links on completion
    """

    _q: "queue.Queue[tuple[str, dict]]"

    def __init__(self) -> None:
        super().__init__()

        self.title(f"{APP_TITLE}  ·  v{APP_VERSION}")
        self.geometry("1200x780")
        self.minsize(1040, 680)
        self.configure(fg_color=CLR_BG)

        # ── State ────────────────────────────────────────────────────────
        self._q = queue.Queue()
        self._selected_folder: Optional[Path] = None
        self._findings: Optional[Dict[str, Any]] = None
        self._case_id: Optional[str] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._submit_thread: Optional[threading.Thread] = None
        # Modal RAR decision helpers
        self._rar_decision_event = threading.Event()
        self._rar_decision_value = False

        # Tk variables — can only live after the root window is created.
        self._include_browsers = ctk.BooleanVar(value=False)
        self._recover_deleted = ctk.BooleanVar(value=True)
        self._upload_evidence = ctk.BooleanVar(value=False)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_statusbar()

        # Drain the cross-thread event queue on the main thread.
        self.after(50, self._drain_queue)

    # ─────────────────────────────────────────────────────────────────
    # Sidebar
    # ─────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        side = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=CLR_SURFACE)
        side.grid(row=0, column=0, sticky="nsew", rowspan=2)
        side.grid_propagate(False)
        side.grid_rowconfigure(99, weight=1)  # push footer to bottom

        # Brand block — diamond logo + product name + tagline
        brand = ctk.CTkFrame(side, fg_color="transparent")
        brand.grid(row=0, column=0, padx=24, pady=(28, 0), sticky="ew")
        logo = ctk.CTkLabel(
            brand, text="◆", width=36, height=36,
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=CLR_ACCENT, fg_color=CLR_ACCENT_SOFT,
            corner_radius=10,
        )
        logo.pack(side="left", padx=(0, 12))
        name_box = ctk.CTkFrame(brand, fg_color="transparent")
        name_box.pack(side="left")
        ctk.CTkLabel(
            name_box, text="Forensic Agent",
            font=ctk.CTkFont(size=17, weight="bold"), text_color=CLR_TEXT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            name_box, text="Local evidence triage",
            font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
        ).pack(anchor="w")

        # Status chip
        self._chip = ctk.CTkLabel(
            side, text="●  Ready",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=CLR_SUCCESS, fg_color=CLR_ELEVATED,
            corner_radius=999, padx=14, pady=6,
        )
        self._chip.grid(row=2, column=0, padx=24, pady=(22, 18), sticky="w")

        # Divider
        self._hairline(side, row=3)

        # Backend config
        self._build_sidebar_backend(side, row=4)

        # Divider
        self._hairline(side, row=5)

        # Privacy note
        privacy = ctk.CTkFrame(
            side, fg_color=CLR_ELEVATED, corner_radius=12,
            border_color=CLR_DIVIDER, border_width=1,
        )
        privacy.grid(row=6, column=0, padx=24, pady=(20, 0), sticky="ew")
        prh = ctk.CTkFrame(privacy, fg_color="transparent")
        prh.pack(fill="x", padx=14, pady=(12, 2))
        ctk.CTkLabel(
            prh, text="🔒",
            font=ctk.CTkFont(size=12), text_color=CLR_SUCCESS,
        ).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            prh, text="PRIVACY",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=CLR_SUCCESS,
        ).pack(side="left")
        ctk.CTkLabel(
            privacy,
            text="Evidence stays on this machine. "
                 "Only the JSON findings — never the raw files — "
                 "are sent to the backend on Submit.",
            justify="left", text_color=CLR_TEXT_DIM,
            font=ctk.CTkFont(size=11), wraplength=210,
        ).pack(anchor="w", padx=14, pady=(2, 14))

        # Footer pinned to bottom via row 99 weight=1
        foot = ctk.CTkFrame(side, fg_color="transparent")
        foot.grid(row=100, column=0, padx=24, pady=(0, 20), sticky="sew")
        ctk.CTkLabel(
            foot, text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
        ).pack(anchor="w")
        ctk.CTkLabel(
            foot, text=f"{platform.system()} {platform.release()}",
            font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
        ).pack(anchor="w")

    def _build_sidebar_backend(self, parent, *, row: int) -> None:
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, padx=24, pady=(18, 6), sticky="ew")

        ctk.CTkLabel(
            wrap, text="BACKEND",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=CLR_MUTED,
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            wrap, text="API URL",
            font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
        ).pack(anchor="w")
        self._entry_url = ctk.CTkEntry(
            wrap, height=34, fg_color=CLR_ELEVATED,
            border_color=CLR_DIVIDER, border_width=1,
            text_color=CLR_TEXT, font=ctk.CTkFont(size=11),
        )
        self._entry_url.pack(fill="x", pady=(2, 10))
        self._entry_url.insert(0, DEFAULT_BACKEND)

        ctk.CTkLabel(
            wrap, text="API Key",
            font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
        ).pack(anchor="w")
        self._entry_key = ctk.CTkEntry(
            wrap, height=34, fg_color=CLR_ELEVATED,
            border_color=CLR_DIVIDER, border_width=1,
            text_color=CLR_TEXT, show="•", font=ctk.CTkFont(size=11),
        )
        self._entry_key.pack(fill="x", pady=(2, 10))
        if DEFAULT_API_KEY:
            self._entry_key.insert(0, DEFAULT_API_KEY)

        btn_row = ctk.CTkFrame(wrap, fg_color="transparent")
        btn_row.pack(fill="x")
        self._btn_test = ctk.CTkButton(
            btn_row, text="Test Connection", height=30,
            fg_color=CLR_ELEVATED, hover_color=CLR_DIVIDER,
            text_color=CLR_TEXT, font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_test_connection,
        )
        self._btn_test.pack(side="left", fill="x", expand=True)
        self._lbl_test = ctk.CTkLabel(
            wrap, text="", font=ctk.CTkFont(size=10),
            text_color=CLR_TEXT_DIM, anchor="w", justify="left", wraplength=220,
        )
        self._lbl_test.pack(anchor="w", pady=(6, 0), fill="x")

    # ─────────────────────────────────────────────────────────────────
    # Main content
    # ─────────────────────────────────────────────────────────────────

    def _build_main(self) -> None:
        main = ctk.CTkScrollableFrame(
            self, fg_color=CLR_BG,
            scrollbar_button_color=CLR_SURFACE,
            scrollbar_button_hover_color=CLR_ELEVATED,
        )
        main.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        main.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(main, fg_color="transparent")
        inner.grid(row=0, column=0, sticky="nsew", padx=36, pady=(32, 24))
        inner.grid_columnconfigure(0, weight=1)

        self._build_header(inner, row=0)
        self._build_card_evidence(inner, row=1)
        self._build_card_run(inner, row=2)
        self._build_card_results(inner, row=3)
        self._build_card_submit(inner, row=4)

    def _build_header(self, parent, *, row: int) -> None:
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.grid(row=row, column=0, sticky="ew", pady=(0, 26))

        # Eyebrow tag
        eyebrow = ctk.CTkLabel(
            hdr, text="NEW INVESTIGATION",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=CLR_ACCENT,
        )
        eyebrow.pack(anchor="w", pady=(0, 6))

        ctk.CTkLabel(
            hdr, text="Folder Forensics Workspace",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            hdr,
            text=("Select a folder on this machine. The agent walks every file "
                  "inside it — hashing, extracting metadata, surfacing recently "
                  "modified items, locating disk images for Sleuth Kit, and "
                  "enumerating the system trash for deleted files you can "
                  "recover. Nothing leaves the machine until you press Submit."),
            font=ctk.CTkFont(size=13), justify="left",
            text_color=CLR_TEXT_DIM, wraplength=860,
        ).pack(anchor="w", pady=(8, 0))

    # ── Card: Evidence picker + options ──────────────────────────────────
    def _build_card_evidence(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._card_header(
            card, step="1", title="Evidence Source",
            subtitle="Select a folder. Every file inside it — and any nested "
                     "subfolders — will be analysed. Single-file selection is "
                     "intentionally not supported; folder context is what makes "
                     "the timeline and deleted-file analysis meaningful.",
        )

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=28, pady=(0, 24))

        # Folder picker row — large, friendly drop-zone style.
        pick_row = ctk.CTkFrame(
            body, fg_color=CLR_SURFACE_2, corner_radius=12,
            border_color=CLR_DIVIDER, border_width=1,
        )
        pick_row.pack(fill="x")

        # Left side: icon + path block
        left = ctk.CTkFrame(pick_row, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True, padx=20, pady=18)
        ctk.CTkLabel(
            left, text="📁", font=ctk.CTkFont(size=28),
            text_color=CLR_ACCENT,
        ).pack(side="left", padx=(0, 14))
        path_col = ctk.CTkFrame(left, fg_color="transparent")
        path_col.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(
            path_col, text="EVIDENCE FOLDER",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=CLR_MUTED, anchor="w",
        ).pack(anchor="w")
        self._lbl_folder = ctk.CTkLabel(
            path_col, text="No folder selected yet.",
            font=ctk.CTkFont(size=13), text_color=CLR_TEXT_DIM,
            anchor="w", justify="left", wraplength=560,
        )
        self._lbl_folder.pack(anchor="w", pady=(2, 0), fill="x")

        # Right side: action button
        ctk.CTkButton(
            pick_row, text="Browse Folder…", height=44, width=180,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H,
            text_color="white", font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=10,
            command=self._on_pick_folder,
        ).pack(side="right", padx=16, pady=14)

        # Capability strip — what the agent will actually do, in plain English.
        cap = ctk.CTkFrame(body, fg_color="transparent")
        cap.pack(fill="x", pady=(14, 0))
        for icon, text in (
            ("🧮", "Hash & inventory every file (MD5 / SHA-256)"),
            ("🕒", f"Surface files modified in the last "
                   f"{DEFAULT_MODIFIED_WINDOW_DAYS} days with timestamps"),
            ("💿", "Auto-detect disk images (.dd / .e01 / .raw / …) → Sleuth Kit"),
            ("🗑", "Enumerate the system Trash / Recycle Bin for deleted files"),
        ):
            row_ = ctk.CTkFrame(cap, fg_color="transparent")
            row_.pack(fill="x", pady=2)
            ctk.CTkLabel(
                row_, text=icon, font=ctk.CTkFont(size=13),
                text_color=CLR_ACCENT, width=24,
            ).pack(side="left")
            ctk.CTkLabel(
                row_, text=text, font=ctk.CTkFont(size=12),
                text_color=CLR_TEXT_DIM, anchor="w",
            ).pack(side="left", padx=(8, 0))

        # Options grid — checkboxes with explanations
        opts = ctk.CTkFrame(body, fg_color="transparent")
        opts.pack(fill="x", pady=(20, 0))
        opts.grid_columnconfigure(0, weight=1)
        opts.grid_columnconfigure(1, weight=1)

        self._option_row(
            opts, row=0, column=0,
            title="Recover deleted files",
            detail="Run Sleuth Kit on any disk image inside the folder AND "
                   "enumerate the OS Trash / Recycle Bin. Carved bytes are "
                   "written to Desktop / TheDeletedFiles.",
            variable=self._recover_deleted,
        )
        self._option_row(
            opts, row=0, column=1,
            title="Include browser history",
            detail="Parse Chrome, Edge, Firefox, Opera, Safari, Brave, Vivaldi "
                   "and Arc history databases. Off by default for privacy.",
            variable=self._include_browsers,
        )

    def _option_row(self, parent, *, row: int, column: int,
                    title: str, detail: str, variable) -> None:
        # Unified card-styled checkbox with a short description beneath it.
        card = ctk.CTkFrame(
            parent, fg_color=CLR_SURFACE_2, corner_radius=10,
            border_color=CLR_DIVIDER, border_width=1,
        )
        card.grid(row=row, column=column, sticky="ew",
                  padx=(0, 8) if column == 0 else (8, 0), pady=0)
        ctk.CTkCheckBox(
            card, text=title, variable=variable,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=CLR_TEXT,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H,
            checkbox_width=20, checkbox_height=20,
        ).pack(anchor="w", padx=18, pady=(16, 6))
        ctk.CTkLabel(
            card, text=detail,
            font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
            justify="left", wraplength=380,
        ).pack(anchor="w", padx=18, pady=(0, 16))

    # ── Card: Run + progress ─────────────────────────────────────────────
    def _build_card_run(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._card_header(
            card, step="2", title="Analyse",
            subtitle="Hashes every file, surfaces recently modified items, "
                     "runs Sleuth Kit on any disk image inside the folder, "
                     "and enumerates the system Trash for deleted files.",
        )

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=28, pady=(0, 24))

        # Start row
        start_row = ctk.CTkFrame(body, fg_color="transparent")
        start_row.pack(fill="x")

        self._btn_start = ctk.CTkButton(
            start_row, text="▶   Start Analysis", height=52, width=240,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H,
            text_color="white", font=ctk.CTkFont(size=15, weight="bold"),
            corner_radius=12,
            command=self._on_start_analysis, state="disabled",
        )
        self._btn_start.pack(side="left")

        self._lbl_run_status = ctk.CTkLabel(
            start_row, text="Pick a folder above to begin.",
            font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
            justify="left", wraplength=600, anchor="w",
        )
        self._lbl_run_status.pack(side="left", padx=(20, 0), fill="x", expand=True)

        # Progress bar
        self._progress = ctk.CTkProgressBar(
            body, height=8, fg_color=CLR_ELEVATED,
            progress_color=CLR_ACCENT, corner_radius=999,
        )
        self._progress.pack(fill="x", pady=(20, 8))
        self._progress.set(0)

        # Current activity line
        self._lbl_current = ctk.CTkLabel(
            body, text=" ", font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=CLR_TEXT_DIM, anchor="w", justify="left",
        )
        self._lbl_current.pack(fill="x")

        # Counter strip
        counters = ctk.CTkFrame(body, fg_color="transparent")
        counters.pack(fill="x", pady=(16, 0))
        self._cnt_files    = self._counter(counters, "Files",    accent=CLR_TEXT)
        self._cnt_modified = self._counter(counters, "Modified", accent=CLR_WARN)
        self._cnt_deleted  = self._counter(counters, "Deleted",  accent=CLR_DANGER)
        self._cnt_trash    = self._counter(counters, "In Trash", accent=CLR_INFO)
        self._cnt_recovered = self._counter(counters, "Recovered", accent=CLR_SUCCESS)
        self._cnt_errors   = self._counter(counters, "Errors",   accent=CLR_FAINT)
        for i, w in enumerate((
            self._cnt_files, self._cnt_modified, self._cnt_deleted,
            self._cnt_trash, self._cnt_recovered, self._cnt_errors,
        )):
            w.pack(side="left", padx=(0, 22) if i < 5 else (0, 0))

    # ── Card: Results (tabbed) ───────────────────────────────────────────
    def _build_card_results(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._card_header(card, step="3", title="Results",
                          subtitle="Summary, modified files (with dates), and recovered "
                                   "deleted files — each on its own tab.")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=28, pady=(0, 22))

        # Empty-state panel, replaced with CTkTabview once analysis runs.
        self._results_body = body
        self._lbl_results_empty = ctk.CTkLabel(
            body, text="Results will appear here once the analysis completes.",
            font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
        )
        self._lbl_results_empty.pack(anchor="w", pady=16)

    # ── Card: Submit + case result ───────────────────────────────────────
    def _build_card_submit(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._card_header(
            card, step="4", title="Publish",
            subtitle="Send the structured findings JSON to the backend and "
                     "receive a Case ID with a shareable report URL plus a "
                     "downloadable PDF.",
        )

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=28, pady=(0, 24))
        self._submit_body = body

        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x")
        self._btn_submit = ctk.CTkButton(
            btn_row, text="Submit Findings", height=46, width=210,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H,
            text_color="white", font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=12, command=self._on_submit, state="disabled",
        )
        self._btn_submit.pack(side="left")
        self._btn_save = ctk.CTkButton(
            btn_row, text="Save JSON…", height=46, width=160,
            fg_color=CLR_ELEVATED, hover_color=CLR_DIVIDER,
            text_color=CLR_TEXT, font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=12, command=self._on_save_json, state="disabled",
        )
        self._btn_save.pack(side="left", padx=(10, 0))

        self._lbl_submit_status = ctk.CTkLabel(
            body, text="Run the analysis to unlock submission.",
            font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
            anchor="w", justify="left", wraplength=700,
        )
        self._lbl_submit_status.pack(anchor="w", pady=(14, 0), fill="x")

        self._case_panel: Optional[ctk.CTkFrame] = None

    # ── Status bar at bottom ─────────────────────────────────────────────
    def _build_statusbar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=CLR_SURFACE, corner_radius=0, height=30)
        bar.grid(row=1, column=1, sticky="sew")
        bar.grid_propagate(False)
        # Top hairline so the status bar reads as a separate region.
        line = ctk.CTkFrame(bar, fg_color=CLR_DIVIDER, height=1)
        line.pack(fill="x", side="top")
        self._sb_label = ctk.CTkLabel(
            bar, text=f"Ready  ·  {platform.system()} {platform.release()}  "
                      f"·  Python {platform.python_version()}",
            font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
        )
        self._sb_label.pack(side="left", padx=22, pady=4)
        ctk.CTkLabel(
            bar, text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=10), text_color=CLR_FAINT,
        ).pack(side="right", padx=22, pady=4)

    # ─────────────────────────────────────────────────────────────────
    # Reusable UI helpers
    # ─────────────────────────────────────────────────────────────────

    def _card(self, parent, *, row: int) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            parent, fg_color=CLR_SURFACE, corner_radius=16,
            border_color=CLR_DIVIDER, border_width=1,
        )
        card.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        return card

    def _card_header(self, parent, *, step: str, title: str, subtitle: str) -> None:
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=28, pady=(24, 18))

        lrow = ctk.CTkFrame(hdr, fg_color="transparent")
        lrow.pack(fill="x")
        badge = ctk.CTkLabel(
            lrow, text=step, width=30, height=30,
            fg_color=CLR_ACCENT_SOFT, text_color=CLR_ACCENT,
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
        )
        badge.pack(side="left", padx=(0, 14))
        ctk.CTkLabel(
            lrow, text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(side="left")

        ctk.CTkLabel(
            hdr, text=subtitle,
            font=ctk.CTkFont(size=12), text_color=CLR_TEXT_DIM,
            justify="left", wraplength=820, anchor="w",
        ).pack(anchor="w", pady=(6, 0), padx=(44, 0))

    def _hairline(self, parent, *, row: int) -> None:
        line = ctk.CTkFrame(parent, fg_color=CLR_DIVIDER, height=1)
        line.grid(row=row, column=0, sticky="ew", padx=24, pady=(18, 0))

    def _counter(self, parent, label: str,
                 accent: Optional[str] = None) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color="transparent")
        v = ctk.CTkLabel(
            f, text="0", font=ctk.CTkFont(size=24, weight="bold"),
            text_color=accent or CLR_TEXT,
        )
        v.pack(anchor="w")
        ctk.CTkLabel(
            f, text=label.upper(),
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=CLR_MUTED,
        ).pack(anchor="w")
        f._value_lbl = v  # type: ignore[attr-defined]
        return f

    def _set_counter(self, widget: ctk.CTkFrame, value: str) -> None:
        widget._value_lbl.configure(text=value)  # type: ignore[attr-defined]

    def _set_chip(self, text: str, color: str) -> None:
        self._chip.configure(text=text, text_color=color)

    def _set_statusbar(self, text: str) -> None:
        self._sb_label.configure(text=text)

    def _stat_card(self, parent, label: str, value: str,
                   accent: Optional[str] = None) -> None:
        card = ctk.CTkFrame(
            parent, fg_color=CLR_SURFACE_2, corner_radius=12,
            border_color=CLR_DIVIDER, border_width=1,
        )
        card.pack(side="left", padx=(0, 10), ipadx=18, ipady=12)
        ctk.CTkLabel(
            card, text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=accent or CLR_TEXT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            card, text=label.upper(),
            font=ctk.CTkFont(size=9, weight="bold"),
            text_color=CLR_MUTED,
        ).pack(anchor="w")

    # ─────────────────────────────────────────────────────────────────
    # Event handlers
    # ─────────────────────────────────────────────────────────────────

    def _on_test_connection(self) -> None:
        url = self._entry_url.get().strip().rstrip("/")
        if not url:
            self._lbl_test.configure(text="Enter a backend URL first.",
                                     text_color=CLR_DANGER)
            return
        self._lbl_test.configure(text="Testing…", text_color=CLR_TEXT_DIM)
        self._btn_test.configure(state="disabled")

        def worker():
            try:
                r = requests.get(f"{url}/api/health", timeout=8)
                ok = r.status_code == 200
                self._q.put(("test_result", {"ok": ok, "status": r.status_code}))
            except Exception as e:
                self._q.put(("test_result", {"ok": False, "error": str(e)}))

        threading.Thread(target=worker, daemon=True).start()

    def _on_pick_folder(self) -> None:
        path = filedialog.askdirectory(
            title="Select an evidence folder to investigate",
            mustexist=True,
        )
        if not path:
            return
        self._selected_folder = Path(path)
        # The picker card already shows a folder icon, so just render the path.
        self._lbl_folder.configure(text=path, text_color=CLR_TEXT)
        self._btn_start.configure(state="normal")
        self._lbl_run_status.configure(
            text="Ready. Press Start Analysis to begin.",
            text_color=CLR_TEXT_DIM,
        )

    def _on_start_analysis(self) -> None:
        if not self._selected_folder:
            messagebox.showwarning(APP_TITLE, "Pick a folder first.")
            return
        if self._scan_thread and self._scan_thread.is_alive():
            return

        # Reset UI
        self._progress.set(0)
        for c in (self._cnt_files, self._cnt_modified, self._cnt_deleted,
                  self._cnt_trash, self._cnt_recovered, self._cnt_errors):
            self._set_counter(c, "0")
        self._clear_results()
        self._reset_submit()
        self._findings = None
        self._case_id = None
        self._btn_start.configure(state="disabled", text="Analyzing…")
        self._lbl_run_status.configure(
            text="Walking folder…", text_color=CLR_ACCENT,
        )
        self._lbl_current.configure(text=" ")
        self._set_chip("●  Analyzing", CLR_ACCENT)
        self._set_statusbar("Analysis in progress…")

        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(
                self._selected_folder,
                bool(self._include_browsers.get()),
                bool(self._recover_deleted.get()),
            ),
            daemon=True,
        )
        self._scan_thread.start()

    def _on_submit(self) -> None:
        if not self._findings:
            return
        if self._submit_thread and self._submit_thread.is_alive():
            return

        url = self._entry_url.get().strip().rstrip("/")
        key = self._entry_key.get().strip()
        if not url:
            messagebox.showerror(APP_TITLE, "Backend URL is empty.")
            return
        if not key:
            messagebox.showerror(APP_TITLE, "API key is required to submit findings.")
            return

        self._btn_submit.configure(state="disabled", text="Submitting…")
        self._lbl_submit_status.configure(
            text="Uploading findings JSON to backend…",
            text_color=CLR_ACCENT,
        )
        self._set_chip("●  Submitting", CLR_ACCENT)

        self._submit_thread = threading.Thread(
            target=self._submit_worker,
            args=(url, key, self._findings),
            daemon=True,
        )
        self._submit_thread.start()

    def _on_save_json(self) -> None:
        if not self._findings:
            return
        path = filedialog.asksaveasfilename(
            title="Save findings JSON",
            defaultextension=".json",
            initialfile="forensic-findings.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._findings, f, indent=2, default=str)
            messagebox.showinfo(APP_TITLE, f"Saved to\n{path}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Save failed:\n{e}")

    # ─────────────────────────────────────────────────────────────────
    # Background workers  (must not touch Tk — use self._q)
    # ─────────────────────────────────────────────────────────────────

    def _scan_worker(self, root: Path, include_browsers: bool,
                     recover_deleted: bool) -> None:
        """
        Main analysis pipeline. Runs entirely on a background thread.

        Phase 1: scanner.py — hashes, metadata, browser history (opt-in).
        Phase 2: auto-detect disk images inside the folder and run TSK on
                 each one if the investigator opted into recovery.
        Phase 3: compute 'recently modified' file list for the summary tab.
        """
        try:
            scanner = _load_scanner()
        except RuntimeError as e:
            self._q.put(("scan_error", {"error": str(e)}))
            return

        def on_progress(done: int, total: int) -> None:
            frac = done / total if total else 0
            # Reserve the last 20 % of the bar for the TSK phase so the bar
            # doesn't jump back when the second phase starts.
            self._q.put(("scan_progress", {
                "done": done, "total": total,
                "fraction": min(frac * 0.8, 0.8) if recover_deleted else frac,
            }))

        def rar_decision(rar_path, count: int) -> bool:
            self._rar_decision_event.clear()
            self._q.put(("rar_prompt", {"path": str(rar_path), "count": count}))
            self._rar_decision_event.wait()
            return self._rar_decision_value

        # ── Phase 1: logical scan ─────────────────────────────────────
        try:
            findings = scanner.scan(
                root,
                rar_decision=rar_decision,
                on_progress=on_progress,
                include_browsers=include_browsers,
            )
        except Exception as e:
            import traceback
            self._q.put(("scan_error", {
                "error": f"{e}\n\n{traceback.format_exc()}",
            }))
            return

        findings["include_browsers"] = include_browsers

        # ── Phase 2: auto-detect disk images & run TSK on them ───────
        tsk_results: List[Dict[str, Any]] = []
        recovered_total = 0
        if recover_deleted:
            disk_images = self._find_disk_images(findings, root)
            if disk_images:
                try:
                    tsk_runner = _load_tsk_runner()
                except RuntimeError as e:
                    self._q.put(("disk_log", {
                        "text": f"(Sleuth Kit module unavailable: {e})"
                    }))
                    tsk_runner = None

                if tsk_runner is not None:
                    for idx, img in enumerate(disk_images, 1):
                        self._q.put(("disk_log", {
                            "text": f"[{idx}/{len(disk_images)}] Sleuth Kit on "
                                    f"{img.name}…",
                        }))
                        result = self._run_tsk_on_image(tsk_runner, img)
                        tsk_results.append(result)
                        if result.get("recovered_count"):
                            recovered_total += int(result["recovered_count"])
                        # Nudge progress bar forward in the reserved 20 %.
                        self._q.put(("disk_log_progress", {
                            "fraction": 0.8 + 0.2 * (idx / len(disk_images)),
                        }))

        findings["tsk_disk_analyses"] = tsk_results
        findings["recovered_total"] = recovered_total

        # ── Phase 3: recently-modified list ──────────────────────────
        findings["modified_recent"] = self._extract_modified(
            findings.get("files") or [],
            window_days=DEFAULT_MODIFIED_WINDOW_DAYS,
        )

        # ── Phase 4: system Trash / Recycle Bin enumeration ──────────
        # Always runs, regardless of recover_deleted. The user explicitly
        # wants to see what's deleted on their machine — the recover_deleted
        # toggle only governs whether we bother to *carve* TSK-level deletions
        # from disk images, not whether we list the OS trash.
        try:
            self._q.put(("disk_log", {
                "text": "Enumerating system Trash / Recycle Bin…",
            }))
            findings["system_trash"] = scan_system_trash()
        except Exception as e:
            findings["system_trash"] = []
            findings.setdefault("errors", []).append({
                "path": "<system trash>",
                "error": f"trash enumeration failed: {e}",
            })

        self._q.put(("scan_done", {"findings": findings}))

    def _find_disk_images(self, findings: Dict[str, Any],
                          root: Path) -> List[Path]:
        """
        Return a list of disk-image file paths within the investigated folder.
        We prefer the scanner's own classification (it already knows what a
        disk_image is) but also fall back to an extension match in case the
        classifier missed something (e.g. a .img file the user dropped in).
        """
        seen: Dict[str, Path] = {}
        for p in findings.get("images_to_upload") or []:
            path = Path(p)
            if path.exists():
                seen[str(path)] = path
        # Belt & braces: glob by extension in case the scanner skipped.
        try:
            if root.is_dir():
                for ext in DISK_IMAGE_EXTS:
                    for hit in root.rglob(f"*{ext}"):
                        if hit.is_file():
                            seen[str(hit)] = hit
        except OSError:
            pass
        return list(seen.values())

    def _run_tsk_on_image(self, tsk_runner, image: Path) -> Dict[str, Any]:
        """
        Execute `LocalTSKRunner(image).analyse(...)` with progress logging
        routed through the event queue. Returns a dict shaped for the
        Deleted-Files tab: image path, partitions, fs info, deleted list,
        recovered list, and the recovery folder.
        """
        def on_log(line: str) -> None:
            self._q.put(("disk_log", {"text": f"  {line}"}))

        try:
            runner = tsk_runner.LocalTSKRunner(image)
            if not runner.is_available:
                return {
                    "image": str(image),
                    "error": runner.why_missing(),
                    "tsk_available": False,
                }
            out_dir = tsk_runner.desktop_deleted_files_dir() / image.stem
            out_dir.mkdir(parents=True, exist_ok=True)
            result = runner.analyse(out_dir, on_log=on_log, deleted_only=True)
            return {
                "image": str(image),
                "image_name": image.name,
                "recovery_path": str(out_dir),
                "partitions": result.get("partitions") or [],
                "fsstat": result.get("fsstat") or {},
                "deleted_files": result.get("deleted_files") or [],
                "recovered_files": result.get("recovered_files") or [],
                "recovered_count": result.get("recovered_count", 0),
                "total_deleted": result.get("total_deleted", 0),
                "tsk_available": True,
            }
        except Exception as e:
            import traceback
            return {
                "image": str(image),
                "error": f"{e}\n\n{traceback.format_exc()}",
                "tsk_available": True,
            }

    def _extract_modified(self, files: List[Dict[str, Any]],
                          *, window_days: int) -> List[Dict[str, Any]]:
        """
        Return entries whose mtime falls within the last `window_days`,
        sorted most-recent-first. Used to drive the Modified-Files tab.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - window_days * 86400
        out: List[Dict[str, Any]] = []
        for f in files:
            mtime_iso = f.get("mtime")
            if not mtime_iso:
                continue
            try:
                dt = datetime.strptime(mtime_iso.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
                ts = dt.replace(tzinfo=timezone.utc).timestamp()
            except (ValueError, TypeError):
                continue
            if ts < cutoff:
                continue
            out.append({
                "path": f.get("path") or f.get("relative_path") or f.get("name") or "",
                "name": f.get("name") or "",
                "type": f.get("type") or "",
                "size": f.get("size") or 0,
                "mtime": mtime_iso,
                "atime": f.get("atime"),
                "ctime": f.get("ctime"),
                "_ts": ts,
            })
        out.sort(key=lambda x: x["_ts"], reverse=True)
        for x in out:
            x.pop("_ts", None)
        return out

    def _submit_worker(self, url: str, key: str,
                       findings: Dict[str, Any]) -> None:
        try:
            headers = {
                "X-API-Key": key,
                "Content-Type": "application/json",
                "User-Agent": f"forensic-agent-gui/{APP_VERSION}",
            }
            r = requests.post(
                f"{url}/api/agent/findings",
                headers=headers,
                data=json.dumps(findings, default=str),
                timeout=120,
            )
            if r.status_code >= 400:
                self._q.put(("submit_error", {
                    "status": r.status_code,
                    "body": r.text[:500],
                }))
                return
            self._q.put(("submit_done", r.json()))
        except Exception as e:
            self._q.put(("submit_error", {"error": str(e)}))

    # ─────────────────────────────────────────────────────────────────
    # Event queue drain — runs on main thread
    # ─────────────────────────────────────────────────────────────────

    def _drain_queue(self) -> None:
        try:
            while True:
                name, payload = self._q.get_nowait()
                self._handle_event(name, payload)
        except queue.Empty:
            pass
        self.after(50, self._drain_queue)

    def _handle_event(self, name: str, p: dict) -> None:
        if name == "test_result":
            if p.get("ok"):
                self._lbl_test.configure(text="✓ Backend reachable.",
                                         text_color=CLR_SUCCESS)
            elif "error" in p:
                self._lbl_test.configure(text=f"✗ {p['error'][:80]}",
                                         text_color=CLR_DANGER)
            else:
                self._lbl_test.configure(text=f"✗ HTTP {p.get('status')}",
                                         text_color=CLR_DANGER)
            self._btn_test.configure(state="normal")

        elif name == "scan_progress":
            self._progress.set(p["fraction"])
            self._lbl_run_status.configure(
                text=f"Scanned {p['done']:,} of {p['total']:,} files "
                     f"({p['fraction']*100:.0f}%)",
                text_color=CLR_ACCENT,
            )
            self._set_counter(self._cnt_files, f"{p['done']:,}")

        elif name == "disk_log":
            self._lbl_current.configure(
                text=p.get("text", "") or " ", text_color=CLR_TEXT_DIM,
            )

        elif name == "disk_log_progress":
            self._progress.set(p.get("fraction", 0.9))

        elif name == "rar_prompt":
            self._show_rar_dialog(p["path"], p["count"])

        elif name == "scan_done":
            self._on_scan_done(p["findings"])

        elif name == "scan_error":
            self._btn_start.configure(state="normal", text="▶  Start Analysis")
            self._lbl_run_status.configure(text="✗ Analysis failed — see dialog.",
                                            text_color=CLR_DANGER)
            self._set_chip("●  Error", CLR_DANGER)
            self._set_statusbar("Error during analysis.")
            messagebox.showerror(APP_TITLE, f"Analysis failed:\n\n{p['error']}")

        elif name == "submit_done":
            self._on_submit_done(p)

        elif name == "submit_error":
            self._btn_submit.configure(state="normal", text="Submit Findings")
            err = p.get("error") or f"HTTP {p.get('status')}: {p.get('body', '')}"
            self._lbl_submit_status.configure(
                text=f"✗ Submit failed: {err[:180]}",
                text_color=CLR_DANGER,
            )
            self._set_chip("●  Error", CLR_DANGER)
            messagebox.showerror(APP_TITLE, f"Submit failed:\n\n{err}")

    # ─────────────────────────────────────────────────────────────────
    # Completion handlers
    # ─────────────────────────────────────────────────────────────────

    def _on_scan_done(self, findings: Dict[str, Any]) -> None:
        self._findings = findings
        self._progress.set(1)

        # Roll up counters.
        summary = findings.get("summary") or {}
        total_files = summary.get("total_files") or len(findings.get("files") or [])
        modified = findings.get("modified_recent") or []
        tsk_list = findings.get("tsk_disk_analyses") or []
        trash_items = findings.get("system_trash") or []
        deleted_total = sum(len(t.get("deleted_files") or []) for t in tsk_list)
        recovered_total = findings.get("recovered_total") or 0
        errors = len(findings.get("errors") or [])

        self._set_counter(self._cnt_files, f"{total_files:,}")
        self._set_counter(self._cnt_modified, f"{len(modified):,}")
        self._set_counter(self._cnt_deleted, f"{deleted_total:,}")
        self._set_counter(self._cnt_trash, f"{len(trash_items):,}")
        self._set_counter(self._cnt_recovered, f"{recovered_total:,}")
        self._set_counter(self._cnt_errors, f"{errors:,}")

        tsk_banner = ""
        if tsk_list:
            tsk_banner = (
                f"  ·  {deleted_total:,} carved, {recovered_total:,} recovered"
            )
        trash_banner = (
            f"  ·  {len(trash_items):,} in OS trash" if trash_items else ""
        )
        self._lbl_run_status.configure(
            text=f"✓ Analysis complete — {total_files:,} files processed"
                 f"{tsk_banner}{trash_banner}.",
            text_color=CLR_SUCCESS,
        )
        self._lbl_current.configure(text=" ")
        self._btn_start.configure(state="normal", text="▶  Re-Analyze")
        self._set_chip("●  Done", CLR_SUCCESS)
        self._set_statusbar(
            f"Done  ·  {total_files:,} files  ·  {len(modified):,} modified  "
            f"·  {deleted_total:,} carved  ·  {len(trash_items):,} in trash  "
            f"·  {recovered_total:,} recovered"
        )

        self._render_results(findings)

        # Unlock submission
        self._btn_submit.configure(state="normal")
        self._btn_save.configure(state="normal")
        self._lbl_submit_status.configure(
            text="Findings JSON is ready. Submit to backend or save locally.",
            text_color=CLR_TEXT_DIM,
        )

    def _on_submit_done(self, data: Dict[str, Any]) -> None:
        self._case_id = data.get("case_id")
        self._btn_submit.configure(state="normal", text="✓ Submitted")
        self._lbl_submit_status.configure(
            text=f"✓ Submitted. Case {self._case_id}.",
            text_color=CLR_SUCCESS,
        )
        self._set_chip("●  Submitted", CLR_SUCCESS)

        # Replace/refresh case panel
        if self._case_panel is not None:
            self._case_panel.destroy()

        url = self._entry_url.get().strip().rstrip("/")
        case_url = f"{url}/case/{self._case_id}"
        pdf_url = f"{url}/api/report/{self._case_id}/pdf"

        panel = ctk.CTkFrame(self._submit_body, fg_color=CLR_ELEVATED,
                             corner_radius=10)
        panel.pack(fill="x", pady=(14, 0))
        self._case_panel = panel

        # ID
        ctk.CTkLabel(
            panel, text="CASE ID",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=CLR_MUTED,
        ).pack(anchor="w", padx=16, pady=(12, 0))
        ctk.CTkLabel(
            panel, text=str(self._case_id),
            font=ctk.CTkFont(size=17, weight="bold", family="Consolas"),
            text_color=CLR_ACCENT,
        ).pack(anchor="w", padx=16, pady=(0, 12))

        btn_row = ctk.CTkFrame(panel, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkButton(
            btn_row, text="Open Case Report", height=38, width=180,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H, text_color="white",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: webbrowser.open(case_url),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Download PDF", height=38, width=140,
            fg_color=CLR_SURFACE, hover_color=CLR_DIVIDER, text_color=CLR_TEXT,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: webbrowser.open(pdf_url),
        ).pack(side="left")

        ctk.CTkLabel(
            panel, text=case_url,
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=CLR_MUTED,
        ).pack(anchor="w", padx=16, pady=(0, 12))

    def _reset_submit(self) -> None:
        self._btn_submit.configure(state="disabled", text="Submit Findings")
        self._btn_save.configure(state="disabled")
        self._lbl_submit_status.configure(
            text="Run the analysis to unlock submission.",
            text_color=CLR_MUTED,
        )
        if self._case_panel is not None:
            self._case_panel.destroy()
            self._case_panel = None

    # ─────────────────────────────────────────────────────────────────
    # RAR decision dialog
    # ─────────────────────────────────────────────────────────────────

    def _show_rar_dialog(self, path: str, count: int) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("RAR archive detected")
        dlg.geometry("520x240")
        dlg.configure(fg_color=CLR_SURFACE)
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(
            dlg, text=f"Found {count} .rar archive{'s' if count != 1 else ''}",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(padx=24, pady=(22, 6), anchor="w")
        ctk.CTkLabel(
            dlg, text=f"Sample: {_short_path(path, 58)}",
            font=ctk.CTkFont(size=11, family="Consolas"),
            text_color=CLR_MUTED,
        ).pack(padx=24, pady=(0, 14), anchor="w")
        ctk.CTkLabel(
            dlg,
            text="Walking RAR contents needs `unrar`. Without it the scan "
                 "still continues — RAR files are hashed, but their contents "
                 "are not recursed.",
            font=ctk.CTkFont(size=12), text_color=CLR_TEXT_DIM,
            justify="left", wraplength=460,
        ).pack(padx=24, pady=(0, 14), anchor="w")

        row = ctk.CTkFrame(dlg, fg_color="transparent")
        row.pack(padx=24, pady=(0, 20), anchor="e")

        def answer(include: bool):
            self._rar_decision_value = include
            self._rar_decision_event.set()
            dlg.destroy()

        ctk.CTkButton(
            row, text="Skip RARs", width=120, height=36,
            fg_color=CLR_ELEVATED, hover_color=CLR_DIVIDER, text_color=CLR_TEXT,
            command=lambda: answer(False),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            row, text="Include contents", width=160, height=36,
            fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H, text_color="white",
            command=lambda: answer(True),
        ).pack(side="left")

        dlg.protocol("WM_DELETE_WINDOW", lambda: answer(False))

    # ─────────────────────────────────────────────────────────────────
    # Results rendering
    # ─────────────────────────────────────────────────────────────────

    def _clear_results(self) -> None:
        for w in self._results_body.winfo_children():
            w.destroy()
        self._lbl_results_empty = ctk.CTkLabel(
            self._results_body,
            text="Results will appear here once the analysis completes.",
            font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
        )
        self._lbl_results_empty.pack(anchor="w", pady=16)

    def _render_results(self, findings: Dict[str, Any]) -> None:
        # Wipe the empty state.
        for w in self._results_body.winfo_children():
            w.destroy()

        # Tabbed layout — Overview / Modified / Deleted / Trash / Errors
        tabs = ctk.CTkTabview(
            self._results_body, fg_color=CLR_SURFACE_2,
            segmented_button_fg_color=CLR_SURFACE,
            segmented_button_selected_color=CLR_ACCENT,
            segmented_button_selected_hover_color=CLR_ACCENT_H,
            segmented_button_unselected_color=CLR_SURFACE,
            segmented_button_unselected_hover_color=CLR_DIVIDER,
            text_color=CLR_TEXT,
            corner_radius=14,
            border_color=CLR_DIVIDER, border_width=1,
        )
        tabs.pack(fill="both", expand=True)

        tab_overview = tabs.add("Overview")
        tab_modified = tabs.add("Modified Files")
        tab_deleted  = tabs.add("Deleted (Disk Image)")
        tab_trash    = tabs.add("System Trash")
        tab_errors   = tabs.add("Errors")

        self._render_overview(tab_overview, findings)
        self._render_modified(tab_modified, findings)
        self._render_deleted(tab_deleted, findings)
        self._render_trash(tab_trash, findings)
        self._render_errors(tab_errors, findings)

        tabs.set("Overview")

    # ── Overview tab ─────────────────────────────────────────────────────
    def _render_overview(self, parent, findings: Dict[str, Any]) -> None:
        summary = findings.get("summary") or {}
        tsk_list = findings.get("tsk_disk_analyses") or []
        modified = findings.get("modified_recent") or []
        trash_items = findings.get("system_trash") or []
        recovered_total = findings.get("recovered_total") or 0

        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=14, pady=14)

        # Stat strip
        strip = ctk.CTkFrame(wrap, fg_color="transparent")
        strip.pack(fill="x", pady=(0, 14))
        self._stat_card(strip, "Total Files",
                        f"{summary.get('total_files', 0):,}")
        self._stat_card(strip, "Total Size",
                        _fmt_size(summary.get("total_size_bytes", 0)))
        self._stat_card(strip, f"Modified ({DEFAULT_MODIFIED_WINDOW_DAYS}d)",
                        f"{len(modified):,}", accent=CLR_WARN)
        deleted_n = sum(len(t.get("deleted_files") or []) for t in tsk_list)
        self._stat_card(strip, "Deleted (Image)",
                        f"{deleted_n:,}", accent=CLR_DANGER)
        self._stat_card(strip, "In OS Trash",
                        f"{len(trash_items):,}", accent=CLR_INFO)
        self._stat_card(strip, "Recovered",
                        f"{recovered_total:,}", accent=CLR_SUCCESS)

        # By-type pills
        by_type = summary.get("by_type") or {}
        if by_type:
            ctk.CTkLabel(
                wrap, text="File types",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=CLR_TEXT_DIM,
            ).pack(anchor="w", pady=(4, 6))
            grid = ctk.CTkFrame(wrap, fg_color="transparent")
            grid.pack(fill="x", pady=(0, 14))
            pill_colors = {
                "image": "#60a5fa", "pdf": "#ef4444", "docx": "#3b82f6",
                "text": "#10b981", "archive_zip": "#a855f7",
                "archive_rar": "#f59e0b", "disk_image": "#f97316",
                "browser_db": "#ec4899", "video": "#22d3ee",
                "other": CLR_MUTED,
            }
            for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
                color = pill_colors.get(t, CLR_MUTED)
                pill = ctk.CTkFrame(grid, fg_color=CLR_SURFACE, corner_radius=8)
                pill.pack(side="left", padx=(0, 8), pady=(0, 8))
                row = ctk.CTkFrame(pill, fg_color="transparent")
                row.pack(padx=12, pady=6)
                ctk.CTkLabel(
                    row, text=t.replace("_", " "),
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=color,
                ).pack(side="left")
                ctk.CTkLabel(
                    row, text=f"{n:,}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=CLR_TEXT,
                ).pack(side="left", padx=(8, 0))

        # Disk-image callout
        if tsk_list:
            callout = ctk.CTkFrame(wrap, fg_color=CLR_SURFACE, corner_radius=10)
            callout.pack(fill="x", pady=(4, 0))
            ctk.CTkLabel(
                callout, text="Sleuth Kit ran on the following disk image(s):",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=CLR_WARN,
            ).pack(anchor="w", padx=16, pady=(12, 4))
            for t in tsk_list:
                if t.get("error"):
                    line = f"✗  {Path(t.get('image', '')).name}  —  {t['error'][:120]}"
                    color = CLR_DANGER
                else:
                    fs = (t.get("fsstat") or {}).get("fs_type", "?")
                    line = (f"✓  {t.get('image_name', '')}  —  "
                            f"{len(t.get('partitions') or [])} partition(s), "
                            f"fs={fs}, "
                            f"{len(t.get('deleted_files') or []):,} deleted, "
                            f"{t.get('recovered_count', 0):,} recovered")
                    color = CLR_SUCCESS
                ctk.CTkLabel(
                    callout, text=line,
                    font=ctk.CTkFont(size=11, family="Consolas"),
                    text_color=color, anchor="w", justify="left",
                    wraplength=780,
                ).pack(anchor="w", padx=16, pady=(0, 2))
            ctk.CTkLabel(callout, text=" ",
                         font=ctk.CTkFont(size=4)).pack()

    # ── Modified Files tab ──────────────────────────────────────────────
    def _render_modified(self, parent, findings: Dict[str, Any]) -> None:
        modified = findings.get("modified_recent") or []
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=14, pady=14)

        ctk.CTkLabel(
            wrap,
            text=f"Files modified in the last {DEFAULT_MODIFIED_WINDOW_DAYS} days "
                 f"({len(modified):,})",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            wrap,
            text="Sorted newest first. Shows the modification (mtime) timestamp, "
                 "size, and type of each file.",
            font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
        ).pack(anchor="w", pady=(0, 12))

        if not modified:
            ctk.CTkLabel(
                wrap, text="No files modified in the selected window.",
                font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
            ).pack(anchor="w", pady=16)
            return

        # Header row
        hdr = ctk.CTkFrame(wrap, fg_color=CLR_SURFACE, corner_radius=6)
        hdr.pack(fill="x")
        for txt, w_, anchor in (
            ("Modified", 150, "w"),
            ("Type", 90, "w"),
            ("Size", 90, "e"),
            ("File", 520, "w"),
        ):
            ctk.CTkLabel(
                hdr, text=txt.upper(), width=w_, anchor=anchor,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=CLR_MUTED,
            ).pack(side="left", padx=(12 if anchor == "w" else 0, 12), pady=8)

        # Data rows inside a scrollable box
        body = ctk.CTkScrollableFrame(
            wrap, fg_color=CLR_SURFACE, height=320,
            scrollbar_button_color=CLR_DIVIDER,
            corner_radius=6,
        )
        body.pack(fill="both", expand=True, pady=(1, 0))

        max_rows = 500
        for entry in modified[:max_rows]:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", padx=4, pady=0)
            ctk.CTkLabel(
                row, text=_fmt_ts(entry.get("mtime")),
                width=150, anchor="w",
                font=ctk.CTkFont(size=11, family="Consolas"),
                text_color=CLR_WARN,
            ).pack(side="left", padx=(12, 12), pady=4)
            ctk.CTkLabel(
                row, text=(entry.get("type") or "").replace("_", " "),
                width=90, anchor="w",
                font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
            ).pack(side="left", padx=(0, 12), pady=4)
            ctk.CTkLabel(
                row, text=_fmt_size(entry.get("size") or 0),
                width=90, anchor="e",
                font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
            ).pack(side="left", padx=(0, 12), pady=4)
            ctk.CTkLabel(
                row, text=_short_path(entry.get("path") or entry.get("name") or "", 82),
                anchor="w", font=ctk.CTkFont(size=11, family="Consolas"),
                text_color=CLR_TEXT, justify="left",
            ).pack(side="left", padx=(0, 12), pady=4, fill="x", expand=True)

        if len(modified) > max_rows:
            ctk.CTkLabel(
                wrap,
                text=f"… and {len(modified) - max_rows:,} more. "
                     f"Full list is in the findings JSON.",
                font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
            ).pack(anchor="w", pady=(8, 0))

    # ── Deleted Files tab ───────────────────────────────────────────────
    def _render_deleted(self, parent, findings: Dict[str, Any]) -> None:
        tsk_list = findings.get("tsk_disk_analyses") or []
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=14, pady=14)

        if not tsk_list:
            ctk.CTkLabel(
                wrap,
                text=("No disk images were found inside the selected folder, "
                      "so there were no deletions to recover."
                      if not findings.get("recover_deleted_requested", True)
                      else "No disk images were found inside the selected folder. "
                           "Drop a .dd / .e01 / .raw / .img file into the folder "
                           "and re-run to recover deleted files from it."),
                font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
                wraplength=720, justify="left",
            ).pack(anchor="w", pady=16)
            return

        for t in tsk_list:
            self._render_tsk_block(wrap, t)

    def _render_tsk_block(self, parent, t: Dict[str, Any]) -> None:
        block = ctk.CTkFrame(parent, fg_color=CLR_SURFACE, corner_radius=10)
        block.pack(fill="x", pady=(0, 12))

        title = ctk.CTkFrame(block, fg_color="transparent")
        title.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            title, text=f"💿  {t.get('image_name') or Path(t.get('image', '')).name}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(side="left")
        ctk.CTkLabel(
            title, text=f"   {t.get('image', '')}",
            font=ctk.CTkFont(size=10, family="Consolas"),
            text_color=CLR_MUTED,
        ).pack(side="left")

        if t.get("error"):
            ctk.CTkLabel(
                block, text=f"✗ {t['error'][:400]}",
                font=ctk.CTkFont(size=11), text_color=CLR_DANGER,
                wraplength=820, justify="left",
            ).pack(anchor="w", padx=16, pady=(0, 14))
            return

        # Quick stats
        fs = t.get("fsstat") or {}
        parts = t.get("partitions") or []
        deleted = t.get("deleted_files") or []
        stats = ctk.CTkFrame(block, fg_color="transparent")
        stats.pack(fill="x", padx=16, pady=(4, 8))
        for label, value, color in (
            ("Filesystem", fs.get("fs_type", "—") or "—", CLR_ACCENT),
            ("Partitions", str(len(parts)), CLR_TEXT),
            ("Deleted", f"{len(deleted):,}", CLR_WARN),
            ("Recovered", f"{t.get('recovered_count', 0):,}", CLR_SUCCESS),
        ):
            chip = ctk.CTkFrame(stats, fg_color=CLR_ELEVATED, corner_radius=8)
            chip.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                chip, text=label, font=ctk.CTkFont(size=10),
                text_color=CLR_MUTED,
            ).pack(anchor="w", padx=12, pady=(8, 0))
            ctk.CTkLabel(
                chip, text=value,
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color=color,
            ).pack(anchor="w", padx=12, pady=(0, 8))

        # Recovery folder + open button
        recovery = t.get("recovery_path")
        if recovery:
            rec_row = ctk.CTkFrame(block, fg_color="transparent")
            rec_row.pack(fill="x", padx=16, pady=(4, 0))
            ctk.CTkLabel(
                rec_row,
                text=f"📂  Recovered files in: {recovery}",
                font=ctk.CTkFont(size=11, family="Consolas"),
                text_color=CLR_ACCENT, anchor="w", justify="left",
                wraplength=620,
            ).pack(side="left", fill="x", expand=True)
            ctk.CTkButton(
                rec_row, text="Open Folder", height=30, width=120,
                fg_color=CLR_ACCENT, hover_color=CLR_ACCENT_H, text_color="white",
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda r=recovery: _open_in_file_manager(r),
            ).pack(side="right")

        # Deleted-files listing
        if deleted:
            recovered_names = {
                (r.get("name") or "").lower()
                for r in (t.get("recovered_files") or [])
            }
            ctk.CTkLabel(
                block,
                text=f"Deleted files ({len(deleted):,}):",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=CLR_TEXT_DIM,
            ).pack(anchor="w", padx=16, pady=(12, 4))
            tbx = ctk.CTkTextbox(
                block, height=200, fg_color=CLR_BG,
                text_color=CLR_TEXT, font=ctk.CTkFont(size=11, family="Consolas"),
                wrap="none",
            )
            tbx.pack(fill="x", padx=16, pady=(0, 8))
            max_rows = 300
            for entry in deleted[:max_rows]:
                inode = str(entry.get("inode") or "?")
                name = entry.get("name") or "(unnamed)"
                base = name.rsplit("/", 1)[-1].lower()
                mark = "✓" if base in recovered_names else "·"
                tbx.insert("end", f"{mark}  {inode:>14}  {name}\n")
            if len(deleted) > max_rows:
                tbx.insert("end", f"\n… and {len(deleted) - max_rows:,} more.\n")
            tbx.configure(state="disabled")
            ctk.CTkLabel(
                block,
                text="✓  carved bytes on disk      ·  metadata only",
                font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
            ).pack(anchor="w", padx=16, pady=(0, 14))

    # ── System Trash tab ────────────────────────────────────────────────
    def _render_trash(self, parent, findings: Dict[str, Any]) -> None:
        """
        Render the OS-level Trash / Recycle Bin enumeration. Each item shows
        its original path (where Windows preserves it via the `$I` sidecar),
        the deletion timestamp, and a hover-friendly source tag.
        """
        items = findings.get("system_trash") or []
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=14, pady=14)

        sysname = platform.system()
        trash_label = {
            "Darwin":  "macOS Trash (~/.Trash)",
            "Windows": "Windows Recycle Bin ($Recycle.Bin on each drive)",
            "Linux":   "Linux XDG Trash (~/.local/share/Trash)",
        }.get(sysname, "System Trash")

        # Header
        ctk.CTkLabel(
            wrap,
            text=f"{trash_label} — {len(items):,} item{'s' if len(items) != 1 else ''}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=CLR_TEXT,
        ).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(
            wrap,
            text="Files the user moved to Trash but never emptied. Use the "
                 "OS file manager to drag them back to their original "
                 "location. Sorted newest deletion first.",
            font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
            justify="left", wraplength=820,
        ).pack(anchor="w", pady=(0, 12))

        if not items:
            empty = ctk.CTkFrame(
                wrap, fg_color=CLR_SURFACE, corner_radius=10,
            )
            empty.pack(fill="x", pady=(8, 0))
            ctk.CTkLabel(
                empty,
                text="The system trash is empty — nothing to recover here.",
                font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
            ).pack(anchor="w", padx=18, pady=18)
            # Quick-action: open the trash folder anyway so the investigator
            # can confirm directly in the file manager.
            trash_path = self._guess_trash_path()
            if trash_path:
                ctk.CTkButton(
                    empty, text=f"Open {trash_label.split(' (')[0]}",
                    height=32, width=240,
                    fg_color=CLR_SURFACE_2, hover_color=CLR_DIVIDER,
                    text_color=CLR_TEXT,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    command=lambda p=trash_path: _open_in_file_manager(p),
                ).pack(anchor="w", padx=18, pady=(0, 18))
            return

        # Action row — open trash + summary chip
        action_row = ctk.CTkFrame(wrap, fg_color="transparent")
        action_row.pack(fill="x", pady=(0, 10))
        total_size = sum(int(i.get("size") or 0) for i in items)
        chip = ctk.CTkLabel(
            action_row,
            text=f"  {len(items):,} items   ·   {_fmt_size(total_size)} total  ",
            fg_color=CLR_ACCENT_SOFT, text_color=CLR_ACCENT,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=999, padx=14, pady=4,
        )
        chip.pack(side="left")
        trash_path = self._guess_trash_path()
        if trash_path:
            ctk.CTkButton(
                action_row, text=f"Open {trash_label.split(' (')[0]}",
                height=32, width=220,
                fg_color=CLR_SURFACE, hover_color=CLR_DIVIDER, text_color=CLR_TEXT,
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda p=trash_path: _open_in_file_manager(p),
            ).pack(side="right")

        # Header row
        hdr = ctk.CTkFrame(wrap, fg_color=CLR_SURFACE, corner_radius=6)
        hdr.pack(fill="x")
        for txt, w_, anchor in (
            ("Deleted", 150, "w"),
            ("Size", 90, "e"),
            ("Source", 170, "w"),
            ("Original / current path", 540, "w"),
        ):
            ctk.CTkLabel(
                hdr, text=txt.upper(), width=w_, anchor=anchor,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=CLR_MUTED,
            ).pack(side="left", padx=(12 if anchor == "w" else 0, 12), pady=8)

        # Data rows
        body = ctk.CTkScrollableFrame(
            wrap, fg_color=CLR_SURFACE, height=320,
            scrollbar_button_color=CLR_DIVIDER, corner_radius=6,
        )
        body.pack(fill="both", expand=True, pady=(1, 0))

        max_rows = 400
        for entry in items[:max_rows]:
            row = ctk.CTkFrame(body, fg_color="transparent")
            row.pack(fill="x", padx=4, pady=0)

            ctk.CTkLabel(
                row, text=_fmt_ts(entry.get("deleted_at")),
                width=150, anchor="w",
                font=ctk.CTkFont(size=11, family="Consolas"),
                text_color=CLR_INFO,
            ).pack(side="left", padx=(12, 12), pady=4)
            ctk.CTkLabel(
                row, text=_fmt_size(entry.get("size") or 0),
                width=90, anchor="e",
                font=ctk.CTkFont(size=11), text_color=CLR_TEXT_DIM,
            ).pack(side="left", padx=(0, 12), pady=4)
            ctk.CTkLabel(
                row, text=entry.get("source", "—"),
                width=170, anchor="w",
                font=ctk.CTkFont(size=11), text_color=CLR_MUTED,
            ).pack(side="left", padx=(0, 12), pady=4)
            display = (
                entry.get("original_path")
                or entry.get("path")
                or entry.get("name") or ""
            )
            ctk.CTkLabel(
                row, text=_short_path(display, 90),
                anchor="w", font=ctk.CTkFont(size=11, family="Consolas"),
                text_color=CLR_TEXT, justify="left",
            ).pack(side="left", padx=(0, 12), pady=4, fill="x", expand=True)

        if len(items) > max_rows:
            ctk.CTkLabel(
                wrap,
                text=f"… and {len(items) - max_rows:,} more. "
                     f"Full list is in the findings JSON.",
                font=ctk.CTkFont(size=10), text_color=CLR_MUTED,
            ).pack(anchor="w", pady=(8, 0))

    def _guess_trash_path(self) -> Optional[str]:
        """Best-effort path to the OS trash so we can open it in Finder/Explorer."""
        sysname = platform.system()
        if sysname == "Darwin":
            p = Path.home() / ".Trash"
            return str(p) if p.exists() else None
        if sysname == "Linux":
            p = Path.home() / ".local" / "share" / "Trash" / "files"
            return str(p) if p.exists() else None
        if sysname == "Windows":
            # The Recycle Bin is a virtual shell folder; opening
            # "shell:RecycleBinFolder" works via explorer.exe.
            try:
                subprocess.Popen(["explorer.exe", "shell:RecycleBinFolder"])
                return None  # already opened inline
            except Exception:
                return None
        return None

    # ── Errors tab ──────────────────────────────────────────────────────
    def _render_errors(self, parent, findings: Dict[str, Any]) -> None:
        errs = findings.get("errors") or []
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True, padx=14, pady=14)

        if not errs:
            ctk.CTkLabel(
                wrap,
                text="No errors. The analysis completed cleanly.",
                font=ctk.CTkFont(size=12), text_color=CLR_MUTED,
            ).pack(anchor="w", pady=16)
            return

        ctk.CTkLabel(
            wrap, text=f"{len(errs):,} file(s) failed to process:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=CLR_DANGER,
        ).pack(anchor="w", pady=(0, 10))

        tbx = ctk.CTkTextbox(
            wrap, fg_color=CLR_SURFACE,
            text_color=CLR_TEXT, font=ctk.CTkFont(size=11, family="Consolas"),
            wrap="word",
        )
        tbx.pack(fill="both", expand=True)
        for err in errs:
            if isinstance(err, dict):
                path = err.get("path", "")
                reason = err.get("error") or err.get("reason") or err.get("message", "")
                tbx.insert("end", f"• {path}\n    {reason}\n\n")
            else:
                tbx.insert("end", f"• {err}\n\n")
        tbx.configure(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Launch the GUI. Called by forensic_agent_gui.py (the PyInstaller entry)."""
    # PyInstaller + macOS multiprocessing safety — no-op when not frozen.
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception:
        pass

    app = ForensicAgentApp()
    app.mainloop()


if __name__ == "__main__":
    main()
