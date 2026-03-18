"""
api/index.py — Vercel Serverless Entry Point
Vercel looks for a callable named `handler` in this file.
Mangum wraps FastAPI into an AWS Lambda / Vercel-compatible handler.
"""

import sys
import os

# ── Add backend/ to Python path so imports work ──
ROOT_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

for p in [BACKEND_DIR, ROOT_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

# ── Import app and the Mangum handler from backend/main.py ──
from main import app  # noqa: F401

try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    # Fallback: expose the raw ASGI app (Vercel can also call this directly)
    handler = app
