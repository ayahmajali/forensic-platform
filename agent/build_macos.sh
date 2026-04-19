#!/usr/bin/env bash
# build_macos.sh — Build both the GUI .app and the CLI binary for macOS.
#
# Produces:
#   dist/ForensicAgent.app              — the double-clickable GUI app
#   dist/forensic-agent-macos           — the CLI binary (for power users)
# Copies to:
#   ../backend/static/downloads/
#
# Usage:
#   chmod +x build_macos.sh
#   ./build_macos.sh
#
# Prerequisites:
#   - macOS 11+ (result is architecture-specific; merge with `lipo` for universal2)
#   - Python 3.11 from Homebrew or python.org
#   - (Optional) brew install exiftool  → richer EXIF extraction at scan time

set -euo pipefail

cd "$(dirname "$0")"

echo "▶ Locating a usable Python ..."
PYBIN=""
for cand in python3.11 python3.12 python3.10 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    PYBIN="$(command -v "$cand")"
    echo "   using $PYBIN ($("$PYBIN" -V))"
    break
  fi
done
if [ -z "$PYBIN" ]; then
  echo "✗ No python3 found. Install it with: brew install python@3.11" >&2
  exit 1
fi

echo "▶ Creating clean build venv ..."
rm -rf .venv-build
"$PYBIN" -m venv .venv-build
# shellcheck disable=SC1091
source .venv-build/bin/activate

echo "▶ Installing dependencies ..."
pip install --upgrade pip wheel
pip install -r requirements.txt
pip install pyinstaller

echo "▶ Wiping previous build artefacts ..."
rm -rf build dist

# ── Common PyInstaller options ─────────────────────────────────────────────
COMMON_OPTS=(
  --onefile
  --collect-submodules click
  --collect-submodules requests
  --collect-submodules tqdm
  --collect-submodules multiprocessing
  --collect-submodules customtkinter
  --hidden-import scanner
  --hidden-import pypdf
  --hidden-import docx
  --hidden-import rarfile
  --hidden-import _socket
  --hidden-import socket
  --hidden-import ssl
  --hidden-import _ssl
  --hidden-import select
  --hidden-import _queue
  --clean
  --noconfirm
)

# ── 1) GUI .app bundle ─────────────────────────────────────────────────────
echo "▶ Building GUI app (ForensicAgent.app) ..."
pyinstaller \
  "${COMMON_OPTS[@]}" \
  --windowed \
  --name "ForensicAgent" \
  --osx-bundle-identifier "com.forensicplatform.agent" \
  forensic_agent_gui.py

# ── 2) CLI binary ──────────────────────────────────────────────────────────
echo "▶ Building CLI binary (forensic-agent-macos) ..."
pyinstaller \
  "${COMMON_OPTS[@]}" \
  --name forensic-agent-macos \
  forensic_agent.py

# ── 3) Ad-hoc code signing ─────────────────────────────────────────────────
# Unsigned apps trigger Gatekeeper ("cannot be opened because the developer
# cannot be verified") on first launch. A real Apple signature requires a
# $99/year Developer ID — overkill for a graduation project. The ad-hoc
# signature below satisfies macOS's integrity check enough that the
# right-click → Open flow works, and keeps the app openable after System
# Integrity Protection's validation.
if [ -d "dist/ForensicAgent.app" ]; then
  echo "▶ Ad-hoc signing ForensicAgent.app ..."
  # Strip any quarantine flags the build may have picked up.
  xattr -cr "dist/ForensicAgent.app" 2>/dev/null || true
  codesign --force --deep --sign - "dist/ForensicAgent.app" \
      2>/dev/null || echo "   (codesign not available — skipping)"
fi
if [ -f "dist/forensic-agent-macos" ]; then
  echo "▶ Ad-hoc signing forensic-agent-macos ..."
  xattr -cr "dist/forensic-agent-macos" 2>/dev/null || true
  codesign --force --sign - "dist/forensic-agent-macos" \
      2>/dev/null || echo "   (codesign not available — skipping)"
fi

# ── Publish to backend/static/downloads ────────────────────────────────────
DEST="../backend/static/downloads"
mkdir -p "$DEST"

# Use `ditto` (Apple's archiver) instead of `zip`. Plain `zip` corrupts
# extended attributes, symlinks, and the ad-hoc signature we just applied,
# which re-triggers Gatekeeper after download. `ditto -c -k` preserves all
# of it and produces an archive Finder can unzip into a runnable .app.
if [ -d "dist/ForensicAgent.app" ]; then
  echo "▶ Archiving app bundle with ditto (preserves signature + xattrs) ..."
  rm -f "$DEST/ForensicAgent-macos.zip"
  ditto -c -k --sequesterRsrc --keepParent \
      "dist/ForensicAgent.app" "$DEST/ForensicAgent-macos.zip"
  echo "   ✓ Published $DEST/ForensicAgent-macos.zip"
fi

if [ -f "dist/forensic-agent-macos" ]; then
  cp "dist/forensic-agent-macos" "$DEST/forensic-agent-macos"
  chmod +x "$DEST/forensic-agent-macos"
  xattr -cr "$DEST/forensic-agent-macos" 2>/dev/null || true
  echo "   ✓ Published $DEST/forensic-agent-macos"
fi

# Source zip (for the "From source" tab on the download page)
echo "▶ Packing source archive ..."
(cd .. && zip -rq "backend/static/downloads/forensic-agent-source.zip" \
     agent/forensic_agent.py \
     agent/forensic_agent_gui.py \
     agent/gui.py \
     agent/scanner.py \
     agent/setup.py \
     agent/requirements.txt \
     agent/README.md 2>/dev/null || true)

echo ""
echo "✅ Done."
echo "   GUI app:      dist/ForensicAgent.app"
echo "   GUI zip:      $DEST/ForensicAgent-macos.zip"
echo "   CLI binary:   $DEST/forensic-agent-macos"
echo ""
echo "   Test the GUI:"
echo "     open dist/ForensicAgent.app"
echo ""
echo "   Test the CLI:"
echo "     ./dist/forensic-agent-macos --help"
