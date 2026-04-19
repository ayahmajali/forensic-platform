"""
gui.py — Graphical interface for the Forensic Agent.

A native desktop application built with CustomTkinter that lets an
investigator point at a folder, watch a local forensic scan run, decide
what to do about RAR archives, and submit the findings to the backend
for report generation — all without touching a terminal.

Design choices
--------------
* CustomTkinter is Tkinter under the hood, so RAM/CPU footprint is tiny
  and the app uses the OS's own widget toolkit. The modern dark skin
  gives it a 2026 look without the weight of Qt.
* All scanning happens in a background `threading.Thread` so the UI
  stays responsive. Progress updates are posted to the main thread via
  `widget.after(0, ...)` — Tk widgets are not thread-safe otherwise.
* The scanner module is imported lazily so the GUI can still launch
  (and show an actionable error) on a machine with missing deps.
* No evidence bytes leave the machine. Only the JSON findings package
  is POSTed to the backend. This is explained to the user in the UI.

Entry point: `main()` — called by forensic_agent_gui.py.
"""

from __future__ import annotations

import json
import os
import platform
import queue
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Third-party imports are lazy so we can render a friendly error dialog
# if the build is missing a dep rather than crashing out.
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
APP_VERSION = "1.0.0"
DEFAULT_BACKEND = os.getenv("FORENSIC_API_URL", "https://forensic-site.onrender.com")
DEFAULT_API_KEY = os.getenv("FORENSIC_API_KEY", "")

# Match the website palette.
COLOR_BG = "#0b1220"
COLOR_PANEL = "#111a2e"
COLOR_CARD = "#172238"
COLOR_ACCENT = "#3b82f6"      # primary blue
COLOR_ACCENT_HOVER = "#2563eb"
COLOR_SUCCESS = "#10b981"
COLOR_WARN = "#f59e0b"
COLOR_DANGER = "#ef4444"
COLOR_MUTED = "#64748b"
COLOR_TEXT = "#e2e8f0"
COLOR_DIM = "#94a3b8"


# ─────────────────────────────────────────────────────────────────────────────
# Scanner loader — imports scanner.py, working whether we're installed as a
# package or running from PyInstaller's temp directory.
# ─────────────────────────────────────────────────────────────────────────────

def _load_scanner():
    """Return the scanner module or raise a RuntimeError with a hint."""
    last_exc = None
    for modname in ("scanner", "agent.scanner"):
        try:
            return __import__(modname, fromlist=["*"])
        except ImportError as e:
            last_exc = e
    raise RuntimeError(f"Could not import scanner module: {last_exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Human-formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_size(nbytes: int) -> str:
    """1234567 -> '1.2 MB'."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{int(nbytes)} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


def _short_path(path: str, limit: int = 60) -> str:
    """Truncate a path in the middle so the filename stays visible."""
    if len(path) <= limit:
        return path
    head = path[: limit // 2 - 2]
    tail = path[-(limit // 2 - 1):]
    return f"{head}…{tail}"


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class ForensicAgentApp(ctk.CTk):
    """
    The main application window.

    Widget tree:
      root
      ├─ sidebar (branding + footer links)
      └─ main_frame
         ├─ step_1_config  (backend URL + API key)
         ├─ step_2_folder  (folder picker)
         ├─ step_3_scan    (progress + current file)
         ├─ step_4_summary (by-type cards + submit button)
         └─ step_5_case    (case ID + Open Report)
    """

    # Event queue for background → main thread messages.
    # Items: (event_name: str, payload: dict)
    _q: "queue.Queue[tuple[str, dict]]"

    def __init__(self) -> None:
        super().__init__()

        self.title(f"{APP_TITLE} {APP_VERSION}")
        self.geometry("1100x720")
        self.minsize(980, 640)
        self.configure(fg_color=COLOR_BG)

        # State
        self._q = queue.Queue()
        self._selected_folder: Optional[Path] = None
        self._findings: Optional[Dict[str, Any]] = None
        self._case_id: Optional[str] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._submit_thread: Optional[threading.Thread] = None
        # Modal RAR decision helpers
        self._rar_decision_event = threading.Event()
        self._rar_decision_value = False

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # ── Grid layout: sidebar (fixed), main (expand) ────────────────────
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

        # Poll the event queue every 50ms.
        self.after(50, self._drain_queue)

    # ─────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────

    def _build_sidebar(self) -> None:
        side = ctk.CTkFrame(
            self, width=260, corner_radius=0, fg_color=COLOR_PANEL,
        )
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(5, weight=1)

        # Brand
        ctk.CTkLabel(
            side, text="⛨  Forensic", font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLOR_TEXT,
        ).grid(row=0, column=0, padx=24, pady=(28, 0), sticky="w")
        ctk.CTkLabel(
            side, text="Agent", font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLOR_ACCENT,
        ).grid(row=1, column=0, padx=24, pady=(0, 24), sticky="w")

        # Status chip
        self._chip = ctk.CTkLabel(
            side, text="● Ready",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_SUCCESS, fg_color=COLOR_CARD,
            corner_radius=999, padx=12, pady=6,
        )
        self._chip.grid(row=2, column=0, padx=24, pady=(0, 8), sticky="w")

        # What it does
        desc = (
            "Scans a folder locally,\n"
            "computes MD5 & SHA-256,\n"
            "extracts metadata, then\n"
            "sends findings to your\n"
            "forensic backend."
        )
        ctk.CTkLabel(
            side, text=desc, justify="left", text_color=COLOR_DIM,
            font=ctk.CTkFont(size=12),
        ).grid(row=3, column=0, padx=24, pady=(16, 8), sticky="w")

        # Privacy callout
        privacy = ctk.CTkFrame(side, fg_color=COLOR_CARD, corner_radius=10)
        privacy.grid(row=4, column=0, padx=24, pady=(8, 0), sticky="ew")
        ctk.CTkLabel(
            privacy, text="Privacy",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_SUCCESS,
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            privacy,
            text="Evidence bytes stay on\nyour machine. Only the\nJSON findings report is\nsent to the backend.",
            justify="left", text_color=COLOR_DIM,
            font=ctk.CTkFont(size=11),
        ).pack(anchor="w", padx=12, pady=(0, 10))

        # Footer
        foot = ctk.CTkFrame(side, fg_color="transparent")
        foot.grid(row=6, column=0, padx=24, pady=(0, 20), sticky="sew")
        ctk.CTkLabel(
            foot, text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=10), text_color=COLOR_MUTED,
        ).pack(anchor="w")
        ctk.CTkLabel(
            foot, text=f"{platform.system()} {platform.release()}",
            font=ctk.CTkFont(size=10), text_color=COLOR_MUTED,
        ).pack(anchor="w")

    def _build_main(self) -> None:
        main = ctk.CTkScrollableFrame(
            self, fg_color=COLOR_BG,
            scrollbar_button_color=COLOR_PANEL,
            scrollbar_button_hover_color=COLOR_CARD,
        )
        main.grid(row=0, column=1, sticky="nsew", padx=24, pady=24)
        main.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(main, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="Run a Forensic Scan",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLOR_TEXT,
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr, text="Point the agent at a folder. It hashes every file, pulls EXIF "
            "and document text, flags disk images, and ships only the findings "
            "to your backend.",
            font=ctk.CTkFont(size=13), justify="left",
            text_color=COLOR_DIM, wraplength=720,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Step 1 — Backend config
        self._build_step_config(main, row=1)

        # Step 2 — Folder picker
        self._build_step_folder(main, row=2)

        # Step 3 — Scan progress
        self._build_step_scan(main, row=3)

        # Step 4 — Summary + submit
        self._build_step_summary(main, row=4)

        # Step 5 — Case result
        self._build_step_case(main, row=5)

    # Step 1 -----------------------------------------------------------------
    def _build_step_config(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._step_header(card, "1", "Connect to your backend")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 20))
        body.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            body, text="Backend URL", font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, padx=(0, 16), pady=8, sticky="w")
        self._entry_url = ctk.CTkEntry(
            body, height=38, fg_color=COLOR_BG, border_color=COLOR_CARD,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=13),
        )
        self._entry_url.grid(row=0, column=1, sticky="ew", pady=8)
        self._entry_url.insert(0, DEFAULT_BACKEND)

        ctk.CTkLabel(
            body, text="API Key", font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=1, column=0, padx=(0, 16), pady=8, sticky="w")
        self._entry_key = ctk.CTkEntry(
            body, height=38, fg_color=COLOR_BG, border_color=COLOR_CARD,
            text_color=COLOR_TEXT, show="•", font=ctk.CTkFont(size=13),
        )
        self._entry_key.grid(row=1, column=1, sticky="ew", pady=8)
        if DEFAULT_API_KEY:
            self._entry_key.insert(0, DEFAULT_API_KEY)

        # Test button
        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._btn_test = ctk.CTkButton(
            btn_row, text="Test Connection", height=34, width=140,
            fg_color=COLOR_CARD, hover_color=COLOR_PANEL,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_test_connection,
        )
        self._btn_test.pack(side="left")
        self._lbl_test = ctk.CTkLabel(
            btn_row, text="", font=ctk.CTkFont(size=12),
            text_color=COLOR_DIM,
        )
        self._lbl_test.pack(side="left", padx=(12, 0))

    # Step 2 -----------------------------------------------------------------
    def _build_step_folder(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._step_header(card, "2", "Choose what to scan")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 20))
        body.grid_columnconfigure(0, weight=1)

        self._lbl_folder = ctk.CTkLabel(
            body, text="No folder selected",
            font=ctk.CTkFont(size=13), text_color=COLOR_DIM,
            anchor="w", justify="left",
        )
        self._lbl_folder.grid(row=0, column=0, sticky="ew", padx=(0, 16))

        btn_frame = ctk.CTkFrame(body, fg_color="transparent")
        btn_frame.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(
            btn_frame, text="Choose Folder…", height=38, width=140,
            fg_color=COLOR_CARD, hover_color=COLOR_PANEL,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_pick_folder,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_frame, text="Choose File…", height=38, width=120,
            fg_color=COLOR_CARD, hover_color=COLOR_PANEL,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_pick_file,
        ).pack(side="left")

    # Step 3 -----------------------------------------------------------------
    def _build_step_scan(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._step_header(card, "3", "Run the scan")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 20))

        # Start button row
        btn_row = ctk.CTkFrame(body, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 12))

        self._btn_scan = ctk.CTkButton(
            btn_row, text="▶  Start Scan", height=44, width=180,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            text_color="white", font=ctk.CTkFont(size=14, weight="bold"),
            command=self._on_start_scan, state="disabled",
        )
        self._btn_scan.pack(side="left")

        self._lbl_scan_status = ctk.CTkLabel(
            btn_row, text="Pick a folder above first.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
        )
        self._lbl_scan_status.pack(side="left", padx=(16, 0))

        # Progress bar
        self._progress = ctk.CTkProgressBar(
            body, height=8, fg_color=COLOR_CARD,
            progress_color=COLOR_ACCENT,
        )
        self._progress.pack(fill="x", pady=(4, 8))
        self._progress.set(0)

        # Current file label
        self._lbl_current = ctk.CTkLabel(
            body, text="", font=ctk.CTkFont(size=11, family="monospace"),
            text_color=COLOR_MUTED, anchor="w", justify="left",
        )
        self._lbl_current.pack(fill="x")

        # Counters row
        counters = ctk.CTkFrame(body, fg_color="transparent")
        counters.pack(fill="x", pady=(8, 0))
        self._lbl_counter_files = self._counter(counters, "Files", "0")
        self._lbl_counter_files.pack(side="left", padx=(0, 24))
        self._lbl_counter_errors = self._counter(counters, "Errors", "0")
        self._lbl_counter_errors.pack(side="left", padx=(0, 24))
        self._lbl_counter_images = self._counter(counters, "Disk images", "0")
        self._lbl_counter_images.pack(side="left")

    # Step 4 -----------------------------------------------------------------
    def _build_step_summary(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._step_header(card, "4", "Review & submit")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 20))
        self._summary_body = body

        self._lbl_summary_empty = ctk.CTkLabel(
            body, text="Scan results will appear here.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
        )
        self._lbl_summary_empty.pack(anchor="w", pady=4)

    # Step 5 -----------------------------------------------------------------
    def _build_step_case(self, parent, *, row: int) -> None:
        card = self._card(parent, row=row)
        self._step_header(card, "5", "Your case")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=24, pady=(0, 20))
        self._case_body = body

        self._lbl_case_empty = ctk.CTkLabel(
            body, text="After submission, your Case ID appears here with a link "
            "to open the report in your browser.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
            wraplength=700, justify="left",
        )
        self._lbl_case_empty.pack(anchor="w", pady=4)

    # ─────────────────────────────────────────────────────────────────────
    # UI helpers
    # ─────────────────────────────────────────────────────────────────────

    def _card(self, parent, *, row: int) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color=COLOR_PANEL, corner_radius=12)
        card.grid(row=row, column=0, sticky="ew", pady=(0, 16))
        return card

    def _step_header(self, parent, num: str, title: str) -> None:
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(20, 12))
        badge = ctk.CTkLabel(
            hdr, text=num, width=28, height=28,
            fg_color=COLOR_ACCENT, text_color="white",
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=999,
        )
        badge.pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            hdr, text=title, font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLOR_TEXT,
        ).pack(side="left")

    def _counter(self, parent, label: str, value: str) -> ctk.CTkFrame:
        f = ctk.CTkFrame(parent, fg_color="transparent")
        v = ctk.CTkLabel(
            f, text=value, font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLOR_TEXT,
        )
        v.pack(anchor="w")
        ctk.CTkLabel(
            f, text=label, font=ctk.CTkFont(size=11),
            text_color=COLOR_MUTED,
        ).pack(anchor="w")
        f._value_lbl = v  # type: ignore[attr-defined]
        return f

    def _set_counter(self, widget: ctk.CTkFrame, value: str) -> None:
        widget._value_lbl.configure(text=value)  # type: ignore[attr-defined]

    def _set_chip(self, text: str, color: str) -> None:
        self._chip.configure(text=text, text_color=color)

    # ─────────────────────────────────────────────────────────────────────
    # Event handlers — button clicks
    # ─────────────────────────────────────────────────────────────────────

    def _on_test_connection(self) -> None:
        url = self._entry_url.get().strip().rstrip("/")
        if not url:
            self._lbl_test.configure(text="Enter a backend URL first.", text_color=COLOR_DANGER)
            return
        self._lbl_test.configure(text="Testing…", text_color=COLOR_DIM)
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
        path = filedialog.askdirectory(title="Select a folder to investigate")
        if path:
            self._selected_folder = Path(path)
            self._lbl_folder.configure(
                text=f"📁  {path}", text_color=COLOR_TEXT,
            )
            self._btn_scan.configure(state="normal")
            self._lbl_scan_status.configure(
                text="Ready to scan.", text_color=COLOR_DIM,
            )

    def _on_pick_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self._selected_folder = Path(path)
            self._lbl_folder.configure(
                text=f"📄  {path}", text_color=COLOR_TEXT,
            )
            self._btn_scan.configure(state="normal")
            self._lbl_scan_status.configure(
                text="Ready to scan.", text_color=COLOR_DIM,
            )

    def _on_start_scan(self) -> None:
        if not self._selected_folder:
            messagebox.showwarning(APP_TITLE, "Pick a folder first.")
            return
        if self._scan_thread and self._scan_thread.is_alive():
            return

        # Reset UI
        self._progress.set(0)
        self._set_counter(self._lbl_counter_files, "0")
        self._set_counter(self._lbl_counter_errors, "0")
        self._set_counter(self._lbl_counter_images, "0")
        self._clear_summary()
        self._clear_case()
        self._findings = None
        self._case_id = None
        self._btn_scan.configure(state="disabled", text="Scanning…")
        self._lbl_scan_status.configure(
            text="Walking the folder…", text_color=COLOR_ACCENT,
        )
        self._set_chip("● Scanning", COLOR_ACCENT)

        # Kick off scanner in a thread.
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(self._selected_folder,),
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
            text="Uploading findings JSON to backend…", text_color=COLOR_ACCENT,
        )
        self._set_chip("● Submitting", COLOR_ACCENT)

        # Only pass through the disk-image list if the user opted in. The
        # checkbox lives on the summary panel and is built in _render_summary.
        upload_images: bool = False
        try:
            upload_images = bool(getattr(self, "_opt_upload_images").get())
        except Exception:
            upload_images = False
        disk_images = list(self._findings.get("images_to_upload") or []) \
            if upload_images else []

        self._submit_thread = threading.Thread(
            target=self._submit_worker,
            args=(url, key, self._findings, disk_images),
            daemon=True,
        )
        self._submit_thread.start()

    # ─────────────────────────────────────────────────────────────────────
    # Background workers — must not touch Tk directly, use the queue.
    # ─────────────────────────────────────────────────────────────────────

    def _scan_worker(self, root: Path) -> None:
        try:
            scanner = _load_scanner()
        except RuntimeError as e:
            self._q.put(("scan_error", {"error": str(e)}))
            return

        def on_progress(done: int, total: int) -> None:
            frac = done / total if total else 0
            self._q.put(("scan_progress", {
                "done": done, "total": total, "fraction": frac,
            }))

        def rar_decision(rar_path, count: int) -> bool:
            # Ask the main thread — block until user answers.
            self._rar_decision_event.clear()
            self._q.put(("rar_prompt", {
                "path": str(rar_path), "count": count,
            }))
            self._rar_decision_event.wait()
            return self._rar_decision_value

        try:
            findings = scanner.scan(
                root,
                rar_decision=rar_decision,
                on_progress=on_progress,
            )
            self._q.put(("scan_done", {"findings": findings}))
        except Exception as e:
            import traceback
            self._q.put(("scan_error", {
                "error": f"{e}\n\n{traceback.format_exc()}",
            }))

    def _submit_worker(
        self,
        url: str,
        key: str,
        findings: Dict[str, Any],
        disk_images: Optional[list] = None,
    ) -> None:
        """
        Two-phase submit:

            1. POST findings JSON → /api/agent/findings          (small, fast)
            2. For each opted-in disk image, POST the raw bytes →
               /api/agent/upload                                  (large, slow)

        Phase 2 is optional — only runs if the user ticked the auto-upload
        checkbox in the summary panel. Each disk-image upload creates its
        own case on the backend (Sleuth Kit needs to walk partitions / run
        mmls, fsstat, fls, tsk_recover etc.), so we return those case IDs
        alongside the logical-scan case ID for the case panel to render.
        """
        disk_images = list(disk_images or [])
        try:
            # ── Phase 1: logical-scan findings ─────────────────────────
            headers = {
                "X-API-Key": key,
                "Content-Type": "application/json",
                "User-Agent": f"forensic-agent-gui/{APP_VERSION}",
            }
            r = requests.post(
                f"{url}/api/agent/findings",
                headers=headers,
                data=json.dumps(findings),
                timeout=90,
            )
            if r.status_code >= 400:
                self._q.put(("submit_error", {
                    "status": r.status_code,
                    "body": r.text[:500],
                }))
                return
            data = r.json()

            # ── Phase 2: disk-image uploads (opt-in) ────────────────────
            disk_cases: list = []
            if disk_images:
                # Per-upload progress so the user knows we haven't hung.
                total = len(disk_images)
                for i, img_path_str in enumerate(disk_images, 1):
                    img_path = Path(img_path_str)
                    if not img_path.exists():
                        disk_cases.append({
                            "path": img_path_str,
                            "error": "File no longer exists on disk.",
                        })
                        continue
                    try:
                        self._q.put(("submit_progress", {
                            "text": f"Uploading disk image {i}/{total}: "
                                    f"{img_path.name} ({_fmt_size(img_path.stat().st_size)})…",
                        }))
                    except Exception:
                        pass
                    try:
                        with img_path.open("rb") as fh:
                            # Stream the file so we don't hold a multi-GB
                            # image in memory. `requests` handles chunking
                            # when `files=` is a file-like object.
                            up = requests.post(
                                f"{url}/api/agent/upload",
                                headers={
                                    "X-API-Key": key,
                                    "User-Agent": f"forensic-agent-gui/{APP_VERSION}",
                                },
                                files={"evidence": (img_path.name, fh, "application/octet-stream")},
                                data={
                                    "keywords": ",".join(findings.get("keywords") or []) or "password,login,bitcoin,admin,secret",
                                    "investigator": findings.get("investigator", "agent"),
                                },
                                # Big timeout for big files — backend needs
                                # time to accept the multipart body. After
                                # upload, TSK runs async in a bg task.
                                timeout=60 * 30,  # 30 minutes
                            )
                        if up.status_code >= 400:
                            disk_cases.append({
                                "path": img_path_str,
                                "error": f"HTTP {up.status_code}: {up.text[:200]}",
                            })
                        else:
                            disk_cases.append({
                                "path": img_path_str,
                                **up.json(),
                            })
                    except Exception as ue:
                        disk_cases.append({
                            "path": img_path_str,
                            "error": str(ue),
                        })
                data["disk_cases"] = disk_cases

            self._q.put(("submit_done", data))
        except Exception as e:
            self._q.put(("submit_error", {"error": str(e)}))

    # ─────────────────────────────────────────────────────────────────────
    # Event queue drain — runs on main thread
    # ─────────────────────────────────────────────────────────────────────

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
                self._lbl_test.configure(
                    text="✓ Backend reachable.", text_color=COLOR_SUCCESS,
                )
            elif "error" in p:
                self._lbl_test.configure(
                    text=f"✗ {p['error'][:60]}", text_color=COLOR_DANGER,
                )
            else:
                self._lbl_test.configure(
                    text=f"✗ HTTP {p.get('status')}", text_color=COLOR_DANGER,
                )
            self._btn_test.configure(state="normal")

        elif name == "scan_progress":
            self._progress.set(p["fraction"])
            self._lbl_scan_status.configure(
                text=f"Scanned {p['done']:,} of {p['total']:,} files "
                     f"({p['fraction']*100:.0f}%)",
                text_color=COLOR_ACCENT,
            )
            self._set_counter(self._lbl_counter_files, f"{p['done']:,}")

        elif name == "rar_prompt":
            self._show_rar_dialog(p["path"], p["count"])

        elif name == "scan_done":
            self._findings = p["findings"]
            self._progress.set(1)
            summary = p["findings"].get("summary", {})
            self._lbl_scan_status.configure(
                text=f"✓ Scan complete — {summary.get('total_files', 0):,} files processed.",
                text_color=COLOR_SUCCESS,
            )
            self._set_counter(self._lbl_counter_files, f"{summary.get('total_files', 0):,}")
            self._set_counter(self._lbl_counter_errors, str(len(p["findings"].get("errors", []))))
            self._set_counter(
                self._lbl_counter_images,
                str(len(p["findings"].get("images_to_upload", []))),
            )
            self._btn_scan.configure(state="normal", text="▶  Scan Again")
            self._set_chip("● Scan done", COLOR_SUCCESS)
            self._render_summary(p["findings"])

        elif name == "scan_error":
            self._btn_scan.configure(state="normal", text="▶  Start Scan")
            self._lbl_scan_status.configure(
                text="✗ Scan failed — see dialog.", text_color=COLOR_DANGER,
            )
            self._set_chip("● Error", COLOR_DANGER)
            messagebox.showerror(APP_TITLE, f"Scan failed:\n\n{p['error']}")

        elif name == "submit_progress":
            # Fired during phase-2 disk image uploads so the user sees
            # "Uploading 1/3: memory.e01 (2.4 GB)…" instead of a frozen UI.
            self._lbl_submit_status.configure(
                text=p.get("text", "Uploading…"),
                text_color=COLOR_ACCENT,
            )

        elif name == "submit_done":
            self._case_id = p.get("case_id")
            self._btn_submit.configure(state="normal", text="✓ Submitted")
            n_disk = len(p.get("disk_cases") or [])
            self._lbl_submit_status.configure(
                text=(
                    f"✓ Findings submitted. {n_disk} disk-image case(s) queued."
                    if n_disk else "✓ Findings submitted."
                ),
                text_color=COLOR_SUCCESS,
            )
            self._set_chip("● Done", COLOR_SUCCESS)
            self._render_case(p)

        elif name == "submit_error":
            self._btn_submit.configure(state="normal", text="Submit to Backend")
            err = p.get("error") or f"HTTP {p.get('status')}: {p.get('body', '')}"
            self._lbl_submit_status.configure(
                text=f"✗ Submit failed: {err[:80]}", text_color=COLOR_DANGER,
            )
            self._set_chip("● Error", COLOR_DANGER)
            messagebox.showerror(APP_TITLE, f"Submit failed:\n\n{err}")

    # ─────────────────────────────────────────────────────────────────────
    # RAR decision dialog
    # ─────────────────────────────────────────────────────────────────────

    def _show_rar_dialog(self, path: str, count: int) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("RAR archive detected")
        dlg.geometry("520x260")
        dlg.configure(fg_color=COLOR_PANEL)
        dlg.transient(self)
        dlg.grab_set()

        ctk.CTkLabel(
            dlg, text=f"Found {count} .rar archive{'s' if count != 1 else ''}",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLOR_TEXT,
        ).pack(padx=24, pady=(24, 6), anchor="w")

        ctk.CTkLabel(
            dlg, text=f"Sample: {_short_path(path, 56)}",
            font=ctk.CTkFont(size=11, family="monospace"),
            text_color=COLOR_MUTED,
        ).pack(padx=24, pady=(0, 14), anchor="w")

        ctk.CTkLabel(
            dlg,
            text="Including RAR contents requires `unrar` (macOS: `brew install "
                 "rar`; Windows: install WinRAR).\n\n"
                 "Without it, the scan still continues — RAR files are hashed, "
                 "but their contents aren't walked.",
            font=ctk.CTkFont(size=12), text_color=COLOR_DIM,
            justify="left", wraplength=460,
        ).pack(padx=24, pady=(0, 16), anchor="w")

        row = ctk.CTkFrame(dlg, fg_color="transparent")
        row.pack(padx=24, pady=(0, 20), anchor="e")

        def answer(include: bool):
            self._rar_decision_value = include
            self._rar_decision_event.set()
            dlg.destroy()

        ctk.CTkButton(
            row, text="Skip RARs", width=120, height=36,
            fg_color=COLOR_CARD, hover_color=COLOR_BG, text_color=COLOR_TEXT,
            command=lambda: answer(False),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            row, text="Include (needs unrar)", width=180, height=36,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color="white",
            command=lambda: answer(True),
        ).pack(side="left")

        dlg.protocol("WM_DELETE_WINDOW", lambda: answer(False))

    # ─────────────────────────────────────────────────────────────────────
    # Summary & case result rendering
    # ─────────────────────────────────────────────────────────────────────

    def _clear_summary(self) -> None:
        for w in self._summary_body.winfo_children():
            w.destroy()
        self._lbl_summary_empty = ctk.CTkLabel(
            self._summary_body, text="Scan results will appear here.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
        )
        self._lbl_summary_empty.pack(anchor="w", pady=4)

    def _render_summary(self, findings: Dict[str, Any]) -> None:
        for w in self._summary_body.winfo_children():
            w.destroy()

        s = findings.get("summary", {})
        by_type = s.get("by_type", {})

        # Cards row — top-level stats
        stats = ctk.CTkFrame(self._summary_body, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 16))
        self._stat_card(stats, "Total Files", f"{s.get('total_files', 0):,}")
        self._stat_card(stats, "Total Size", _fmt_size(s.get("total_size_bytes", 0)))
        self._stat_card(stats, "With Metadata", f"{s.get('with_exif', 0):,}")
        self._stat_card(stats, "Text Extracted", f"{s.get('with_text', 0):,}")

        # By-type grid
        if by_type:
            ctk.CTkLabel(
                self._summary_body, text="File types",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLOR_DIM,
            ).pack(anchor="w", pady=(4, 8))

            grid = ctk.CTkFrame(self._summary_body, fg_color="transparent")
            grid.pack(fill="x", pady=(0, 16))
            for i, (t, n) in enumerate(sorted(by_type.items(), key=lambda x: -x[1])):
                self._type_pill(grid, t, n).pack(
                    side="left", padx=(0, 8), pady=(0, 8),
                )

        # Disk images & RAR warnings
        imgs = findings.get("images_to_upload", [])
        # Default: off — uploading a multi-GB disk image over a cold-start
        # free-tier backend can time out. Investigator opts in explicitly.
        self._opt_upload_images = ctk.BooleanVar(value=False)
        if imgs:
            box = ctk.CTkFrame(self._summary_body, fg_color=COLOR_CARD, corner_radius=8)
            box.pack(fill="x", pady=(4, 8))
            ctk.CTkLabel(
                box, text=f"💿  {len(imgs)} disk image(s) flagged for server-side TSK",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLOR_WARN,
            ).pack(anchor="w", padx=12, pady=(8, 2))
            # Detail rows so the user can see exactly *which* disk images
            # the scanner found before agreeing to upload them.
            for p in imgs[:5]:
                ctk.CTkLabel(
                    box, text=f"   • {p}",
                    font=ctk.CTkFont(size=11, family="monospace"),
                    text_color=COLOR_DIM,
                ).pack(anchor="w", padx=12)
            if len(imgs) > 5:
                ctk.CTkLabel(
                    box, text=f"   … and {len(imgs) - 5} more",
                    font=ctk.CTkFont(size=11), text_color=COLOR_MUTED,
                ).pack(anchor="w", padx=12)
            ctk.CTkCheckBox(
                box,
                text="Also upload these disk images for Sleuth Kit analysis "
                     "(may take several minutes)",
                variable=self._opt_upload_images,
                font=ctk.CTkFont(size=12),
                text_color=COLOR_TEXT,
                fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            ).pack(anchor="w", padx=12, pady=(6, 10))

        errs = findings.get("errors", [])
        if errs:
            box = ctk.CTkFrame(self._summary_body, fg_color=COLOR_CARD, corner_radius=8)
            box.pack(fill="x", pady=(4, 8))
            ctk.CTkLabel(
                box, text=f"⚠  {len(errs)} file(s) failed — see findings JSON for details",
                font=ctk.CTkFont(size=12),
                text_color=COLOR_DIM,
            ).pack(anchor="w", padx=12, pady=8)

        # Submit button
        submit_row = ctk.CTkFrame(self._summary_body, fg_color="transparent")
        submit_row.pack(fill="x", pady=(16, 0))

        self._btn_submit = ctk.CTkButton(
            submit_row, text="Submit to Backend", height=44, width=220,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            text_color="white", font=ctk.CTkFont(size=14, weight="bold"),
            command=self._on_submit,
        )
        self._btn_submit.pack(side="left")

        self._btn_save = ctk.CTkButton(
            submit_row, text="Save JSON…", height=44, width=140,
            fg_color=COLOR_CARD, hover_color=COLOR_BG,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=13, weight="bold"),
            command=self._on_save_json,
        )
        self._btn_save.pack(side="left", padx=(12, 0))

        self._lbl_submit_status = ctk.CTkLabel(
            submit_row, text="Findings will be POSTed to /api/agent/findings.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
        )
        self._lbl_submit_status.pack(side="left", padx=(16, 0))

    def _stat_card(self, parent, label: str, value: str) -> None:
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=10)
        card.pack(side="left", padx=(0, 12), ipadx=14, ipady=8)
        ctk.CTkLabel(
            card, text=value, font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLOR_TEXT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            card, text=label, font=ctk.CTkFont(size=11),
            text_color=COLOR_MUTED,
        ).pack(anchor="w")

    def _type_pill(self, parent, ftype: str, n: int) -> ctk.CTkFrame:
        colors = {
            "image": "#3b82f6", "pdf": "#ef4444", "docx": "#2563eb",
            "text": "#10b981", "archive_zip": "#a855f7", "archive_rar": "#f59e0b",
            "disk_image": "#f97316", "other": COLOR_MUTED,
        }
        color = colors.get(ftype, COLOR_MUTED)
        pill = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=8)
        row = ctk.CTkFrame(pill, fg_color="transparent")
        row.pack(padx=10, pady=6)
        ctk.CTkLabel(
            row, text=ftype.replace("_", " "),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=color,
        ).pack(side="left")
        ctk.CTkLabel(
            row, text=f"{n:,}", font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_TEXT,
        ).pack(side="left", padx=(8, 0))
        return pill

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
                json.dump(self._findings, f, indent=2)
            messagebox.showinfo(APP_TITLE, f"Saved to\n{path}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Save failed:\n{e}")

    def _clear_case(self) -> None:
        for w in self._case_body.winfo_children():
            w.destroy()
        self._lbl_case_empty = ctk.CTkLabel(
            self._case_body, text="After submission, your Case ID appears here.",
            font=ctk.CTkFont(size=12), text_color=COLOR_MUTED,
        )
        self._lbl_case_empty.pack(anchor="w", pady=4)

    def _render_case(self, data: Dict[str, Any]) -> None:
        for w in self._case_body.winfo_children():
            w.destroy()

        case_id = data.get("case_id", "")
        url = self._entry_url.get().strip().rstrip("/")
        # Backend routes (defined in backend/main.py):
        #   /results/{case_id}   — HTML case view
        #   /report/{case_id}    — PDF download
        case_url = f"{url}/results/{case_id}"
        report_url = f"{url}/report/{case_id}"

        # ID row
        id_row = ctk.CTkFrame(self._case_body, fg_color=COLOR_CARD, corner_radius=10)
        id_row.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            id_row, text="Case ID",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_DIM,
        ).pack(anchor="w", padx=16, pady=(12, 0))
        ctk.CTkLabel(
            id_row, text=case_id,
            font=ctk.CTkFont(size=18, weight="bold", family="monospace"),
            text_color=COLOR_ACCENT,
        ).pack(anchor="w", padx=16, pady=(0, 12))

        # Status
        if data.get("status"):
            ctk.CTkLabel(
                self._case_body,
                text=f"Status: {data['status']}",
                font=ctk.CTkFont(size=12), text_color=COLOR_DIM,
            ).pack(anchor="w", pady=(0, 12))

        # Buttons
        btn_row = ctk.CTkFrame(self._case_body, fg_color="transparent")
        btn_row.pack(fill="x")

        ctk.CTkButton(
            btn_row, text="🌐  Open Case in Browser", height=42, width=220,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
            text_color="white", font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: webbrowser.open(case_url),
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="📄  Download PDF Report", height=42, width=200,
            fg_color=COLOR_CARD, hover_color=COLOR_BG,
            text_color=COLOR_TEXT, font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: webbrowser.open(report_url),
        ).pack(side="left")

        ctk.CTkLabel(
            self._case_body,
            text=f"{case_url}",
            font=ctk.CTkFont(size=10, family="monospace"),
            text_color=COLOR_MUTED,
        ).pack(anchor="w", pady=(12, 0))

        # ── Disk-image sub-cases ────────────────────────────────────────
        # If the user opted into server-side TSK analysis, each disk image
        # becomes its own case. Render them as a secondary list — status
        # starts as "queued" and the backend processes them async via the
        # `run_full_analysis` background task.
        disk_cases = data.get("disk_cases") or []
        if disk_cases:
            ctk.CTkLabel(
                self._case_body,
                text=f"Disk images sent for Sleuth Kit analysis ({len(disk_cases)})",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=COLOR_DIM,
            ).pack(anchor="w", pady=(20, 8))

            for dc in disk_cases:
                sub = ctk.CTkFrame(self._case_body, fg_color=COLOR_CARD, corner_radius=8)
                sub.pack(fill="x", pady=(0, 8))

                if "error" in dc:
                    ctk.CTkLabel(
                        sub,
                        text=f"✗  {os.path.basename(dc.get('path', ''))}",
                        font=ctk.CTkFont(size=12, weight="bold"),
                        text_color=COLOR_DANGER,
                    ).pack(anchor="w", padx=12, pady=(10, 0))
                    ctk.CTkLabel(
                        sub, text=dc["error"],
                        font=ctk.CTkFont(size=11), text_color=COLOR_MUTED,
                        wraplength=620, justify="left",
                    ).pack(anchor="w", padx=12, pady=(0, 10))
                    continue

                sub_case_id = dc.get("case_id") or dc.get("job_id", "")
                sub_case_url = f"{url}/results/{sub_case_id}"
                sub_report_url = f"{url}/report/{sub_case_id}"

                top = ctk.CTkFrame(sub, fg_color="transparent")
                top.pack(fill="x", padx=12, pady=(10, 2))
                ctk.CTkLabel(
                    top,
                    text=f"💿  {os.path.basename(dc.get('path', ''))}",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=COLOR_TEXT,
                ).pack(side="left")
                ctk.CTkLabel(
                    top,
                    text=f"  case {sub_case_id}",
                    font=ctk.CTkFont(size=11, family="monospace"),
                    text_color=COLOR_ACCENT,
                ).pack(side="left")
                ctk.CTkLabel(
                    top,
                    text=f"  · {dc.get('status', 'queued')}",
                    font=ctk.CTkFont(size=11),
                    text_color=COLOR_WARN,
                ).pack(side="left")

                btns = ctk.CTkFrame(sub, fg_color="transparent")
                btns.pack(fill="x", padx=12, pady=(2, 10))
                ctk.CTkButton(
                    btns, text="Open in Browser", height=30, width=140,
                    fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                    text_color="white", font=ctk.CTkFont(size=11, weight="bold"),
                    command=lambda u=sub_case_url: webbrowser.open(u),
                ).pack(side="left", padx=(0, 6))
                ctk.CTkButton(
                    btns, text="Download PDF", height=30, width=120,
                    fg_color=COLOR_BG, hover_color=COLOR_PANEL,
                    text_color=COLOR_TEXT, font=ctk.CTkFont(size=11, weight="bold"),
                    command=lambda u=sub_report_url: webbrowser.open(u),
                ).pack(side="left")

            ctk.CTkLabel(
                self._case_body,
                text="Sleuth Kit runs asynchronously on the backend — "
                     "refresh the case page in a minute or two if analysis "
                     "is still queued.",
                font=ctk.CTkFont(size=10), text_color=COLOR_MUTED,
                wraplength=640, justify="left",
            ).pack(anchor="w", pady=(6, 0))


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
