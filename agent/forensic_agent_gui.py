#!/usr/bin/env python3
"""
forensic_agent_gui.py — Entry point for the GUI desktop app.

This is the script PyInstaller bundles into a windowed binary (no console)
for macOS and Windows. It's intentionally thin: all the UI code lives in
gui.py so that it can also be imported directly (`python -m agent.gui`)
during development.

The `multiprocessing.freeze_support()` call is *critical* on macOS —
PyInstaller's one-file bundle re-executes the binary as a child process
for the multiprocessing subsystem, and without this call the child keeps
trying to open the GUI and eventually crashes.
"""

from __future__ import annotations

import multiprocessing
import os
import platform
import sys


def _ensure_admin_windows() -> None:
    """
    On Windows, make sure the agent is running with administrator rights
    BEFORE the GUI even draws. This is what investigators expect — they
    double-click the .exe, see the UAC prompt once, accept it, and from
    then on every action (raw-disk reads, PhotoRec carving, etc.) just
    works without popping additional prompts mid-flow.

    Implementation:
      • If we're already elevated → return, business as usual.
      • If not, ShellExecuteW with the "runas" verb relaunches the same
        executable, telling Windows to surface the UAC consent dialog.
        The current (un-elevated) process then exits, and the user
        interacts with the elevated child.
      • If the user declines UAC, ShellExecuteW returns ≤32 and we exit
        with a friendly stderr message — the GUI never appears, which
        is the right behaviour ("admin was required and you said no").
    """
    if platform.system() != "Windows":
        return  # macOS / Linux handle elevation per-operation
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return  # already elevated, nothing to do
    except Exception:
        # ctypes/shell32 unavailable — best-effort: don't block startup
        return

    # Re-launch self with elevation. We pass through any CLI args.
    # ShellExecuteW returns the result of CreateProcess; values >32 are
    # success, ≤32 are documented error codes (5 = ACCESS_DENIED, which
    # is what you get when the user clicks "No" on UAC).
    try:
        import ctypes
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(
            None,                # hwnd
            "runas",             # verb → triggers UAC consent prompt
            sys.executable,      # this exe (or python.exe in dev)
            params,              # forwarded args
            None,                # working dir
            1,                   # SW_SHOWNORMAL
        )
        if rc <= 32:
            sys.stderr.write(
                "Forensic Agent needs administrator rights to read raw "
                "block devices for deep file recovery. UAC was declined "
                "or the relaunch failed (code "
                f"{rc}). The application will now exit.\n"
            )
            sys.exit(1)
        # Successful relaunch — quietly exit the un-elevated parent so
        # the elevated child becomes the live process.
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Could not auto-elevate: {e}\n")
        # Fall through and let the GUI try anyway — Deep Recovery will
        # surface a friendlier error in-app if it can't read the device.


def main() -> None:
    # Must be the first thing called in frozen apps on macOS/Windows.
    multiprocessing.freeze_support()

    # Pop UAC up-front on Windows so subsequent admin actions are silent.
    # No-op on macOS/Linux (those use per-operation native prompts).
    _ensure_admin_windows()

    try:
        from gui import main as gui_main
    except ImportError:
        # Fallback for when the agent is installed as a package.
        from agent.gui import main as gui_main

    gui_main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # If the GUI never gets off the ground, show a native dialog so the
        # user isn't staring at a silently-quit .app.
        import traceback
        tb = traceback.format_exc()
        sys.stderr.write(tb)
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            root = _tk.Tk()
            root.withdraw()
            _mb.showerror(
                "Forensic Agent — failed to start",
                f"{e}\n\nFull traceback:\n{tb[-1500:]}",
            )
        except Exception:
            pass
        sys.exit(1)
