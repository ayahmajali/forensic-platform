#!/usr/bin/env bash
# build_macos.sh — Build a single-file macOS binary for the forensic agent.
#
# Produces:  dist/forensic-agent-macos
# Copies to: ../backend/static/downloads/forensic-agent-macos
#
# Usage:
#   chmod +x build_macos.sh
#   ./build_macos.sh
#
# Prerequisites:
#   - macOS 11+ (either Intel or Apple Silicon; the result is architecture-
#     specific — build on both and merge with `lipo -create` for universal2)
#   - Python 3.11 from Homebrew or python.org
#   - `brew install exiftool` (optional, enables EXIF in the built binary —
#     but note: exiftool is NOT bundled; users install it separately)

set -euo pipefail

cd "$(dirname "$0")"

echo "▶ Locating a usable Python ..."
# Prefer 3.11 (matches the backend), fall back to whatever `python3` resolves to.
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
# Optional richer parsers so the frozen binary can handle them out of the box.
pip install pypdf python-docx rarfile || true

echo "▶ Running PyInstaller ..."
rm -rf build dist
pyinstaller \
  --onefile \
  --name forensic-agent-macos \
  --collect-submodules click \
  --collect-submodules requests \
  --collect-submodules tqdm \
  --hidden-import scanner \
  --hidden-import pypdf \
  --hidden-import docx \
  --hidden-import rarfile \
  --clean \
  --noconfirm \
  forensic_agent.py

echo "▶ Copying binary to backend/static/downloads ..."
DEST="../backend/static/downloads"
mkdir -p "$DEST"
cp dist/forensic-agent-macos "$DEST/forensic-agent-macos"
chmod +x "$DEST/forensic-agent-macos"

# Also pack a source zip for the "From source" tab on the download page.
echo "▶ Packing source archive ..."
(cd .. && zip -rq "backend/static/downloads/forensic-agent-source.zip" \
     agent/forensic_agent.py \
     agent/scanner.py \
     agent/setup.py \
     agent/requirements.txt \
     agent/README.md 2>/dev/null || true)

echo ""
echo "✅ Done."
echo "   Binary:    dist/forensic-agent-macos ($(du -h dist/forensic-agent-macos | cut -f1))"
echo "   Published: $DEST/forensic-agent-macos"
echo ""
echo "   Test it:"
echo "     ./dist/forensic-agent-macos --help"
