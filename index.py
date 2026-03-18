"""
index.py — Root-level Vercel Serverless Entry Point

@vercel/python requires:
  - entrypoint at ROOT level (index.py)
  - requirements.txt at ROOT level (same directory)

All paths resolve relative to /var/task/ on Vercel.
"""

import sys
import os

# ── Path setup: make backend/ and backend/modules/ importable ──────────────────
_ROOT    = os.path.dirname(os.path.abspath(__file__))          # /var/task
_BACKEND = os.path.join(_ROOT, "backend")                      # /var/task/backend
_MODULES = os.path.join(_BACKEND, "modules")                   # /var/task/backend/modules

for _p in [_BACKEND, _MODULES, _ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Import FastAPI app from backend/main.py ────────────────────────────────────
from main import app  # noqa: E402

# ── Mangum: wraps FastAPI ASGI for Vercel / AWS Lambda ────────────────────────
from mangum import Mangum

handler = Mangum(app, lifespan="off")
