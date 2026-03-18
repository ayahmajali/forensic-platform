"""
api/index.py — Vercel Serverless Entry Point
This file is the bridge between Vercel's Python runtime and the FastAPI app.
Vercel looks for this file automatically when you put it in the /api folder.
"""

import sys
import os

# ── Add the backend folder to Python's module search path ──
# This lets Python find: main.py, modules/, templates/, static/
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ── Import the FastAPI app from backend/main.py ──
from main import app  # noqa: F401 — Vercel needs this imported here
