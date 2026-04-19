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
import sys


def main() -> None:
    # Must be the first thing called in frozen apps on macOS/Windows.
    multiprocessing.freeze_support()

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
