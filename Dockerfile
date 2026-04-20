# syntax=docker/dockerfile:1
#
# Forensic platform — backend container image.
#
# Switched from Render's native Python runtime to Docker because we need
# system-level tools that apt-get install requires root for:
#
#   • sleuthkit      — the core TSK CLI suite (mmls, fls, ils, fsstat, icat,
#                      tsk_recover, mactime) driving modules/disk_analysis.py
#   • libewf-utils   — ewfmount / ewfinfo for E01 (EnCase) image support
#   • libewf-dev     — headers so sleuthkit can parse .e01 segments
#   • libimage-exiftool-perl — exiftool, used by the scanner for EXIF/GPS
#
# Everything the Python buildpack did before (pip install -r requirements.txt,
# uvicorn on $PORT) is reproduced here. Render picks this up via
# `runtime: docker` + `dockerfilePath: ./Dockerfile` in render.yaml.

FROM python:3.11-slim-bookworm

# ── Environment ──────────────────────────────────────────────────────────
# PYTHONUNBUFFERED: stream logs straight to Render's log tail, no buffering.
# PYTHONDONTWRITEBYTECODE: don't litter the image with .pyc files.
# PIP_NO_CACHE_DIR: keep the layer small.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# ── System dependencies ──────────────────────────────────────────────────
# sleuthkit ships mmls/fls/ils/fsstat/icat/tsk_recover.
# libewf-utils / libewf-dev give us E01 (Expert Witness) image support, the
# format police agencies actually ship. Without libewf, `mmls some.e01`
# returns "Cannot determine file system type".
# libimage-exiftool-perl = exiftool (used by modules/scanner where present).
# ca-certificates + curl are harmless but helpful for health checks / debug.
RUN apt-get update && apt-get install -y --no-install-recommends \
        sleuthkit \
        libewf-utils \
        libewf-dev \
        libimage-exiftool-perl \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Sanity check at build time — fail fast if the TSK binaries aren't actually
# on PATH. Cheaper than finding out at runtime.
RUN mmls -V && fls -V && tsk_recover -V && exiftool -ver

# ── Python dependencies ──────────────────────────────────────────────────
WORKDIR /app

# Copy requirements first so pip install is cached when only source changes.
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# ── Application source ───────────────────────────────────────────────────
# Copy just the backend/ directory — we don't need the agent sources, the
# cloudflare-frontend, docs, or .git inside the container. The .dockerignore
# at the repo root whittles the build context down before COPY runs.
COPY backend /app

# ── Runtime ──────────────────────────────────────────────────────────────
# Render sets $PORT at runtime (usually 10000 on free tier). Fall back to 8000
# so `docker run -p 8000:8000 forensic` also works locally.
ENV PORT=8000
EXPOSE 8000

# Use a shell so ${PORT} expands. `exec` so uvicorn becomes PID 1 and gets
# SIGTERM directly on container stop.
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT}
