"""
api/index.py — Vercel Serverless Entry Point

Vercel deploys this file as the Lambda function.
It reads requirements.txt from THIS same api/ directory.
The backend/ folder is added to sys.path so all modules resolve correctly.
"""

import sys
import os

# ── Resolve paths ──────────────────────────────────────────────────────────────
# On Vercel, files land at /var/task/
# __file__ = /var/task/api/index.py
# ROOT     = /var/task
# BACKEND  = /var/task/backend

_HERE       = os.path.dirname(os.path.abspath(__file__))          # /var/task/api
_ROOT       = os.path.dirname(_HERE)                               # /var/task
_BACKEND    = os.path.join(_ROOT, "backend")                       # /var/task/backend
_MODULES    = os.path.join(_BACKEND, "modules")                    # /var/task/backend/modules

# Insert backend and root so Python can find main.py and modules/
for _p in [_BACKEND, _ROOT, _MODULES]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Import the FastAPI app ─────────────────────────────────────────────────────
from main import app  # noqa: E402  (backend/main.py)

# ── Wrap with Mangum for Vercel / AWS Lambda ASGI ─────────────────────────────
from mangum import Mangum

handler = Mangum(app, lifespan="off")
