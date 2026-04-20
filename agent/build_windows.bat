@echo off
REM build_windows.bat - Build both the GUI .exe and the CLI binary for Windows.
REM
REM Produces:
REM   dist\ForensicAgent.exe              - the double-clickable GUI app
REM   dist\forensic-agent-windows.exe     - the CLI binary (for power users)
REM Copies to:
REM   ..\backend\static\downloads\
REM
REM Usage (PowerShell or cmd):
REM     cd agent
REM     .\build_windows.bat
REM
REM Prerequisites:
REM   - Windows 10/11 x64
REM   - Python 3.11 from https://python.org (add to PATH)

setlocal
cd /d "%~dp0"

REM --- Pre-flight: Python 3.11 must be on PATH ---------------------------------
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python is not on PATH.
  echo         Install Python 3.11 from https://www.python.org/downloads/windows/
  echo         and tick "Add python.exe to PATH" during installation.
  exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  Detected Python %PYVER%
echo %PYVER% | findstr /r /c:"^3\.11\." >nul
if errorlevel 1 (
  echo [WARN]  This build script is tested on Python 3.11.x.
  echo         You have %PYVER% — customtkinter + PyInstaller may misbehave on 3.12+.
  echo         Continue anyway? Press Ctrl+C to abort, any other key to continue.
  pause >nul
)

echo  Creating clean build venv ...
python -m venv .venv-build
call .venv-build\Scripts\activate.bat

echo  Installing dependencies ...
python -m pip install --upgrade pip wheel
pip install -r requirements.txt
pip install pyinstaller

echo  Wiping previous build artefacts ...
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist

REM === 1) GUI .exe (windowed, no console) =====================================
echo  Building GUI app (ForensicAgent.exe) ...
pyinstaller ^
  --onefile ^
  --windowed ^
  --name ForensicAgent ^
  --collect-submodules click ^
  --collect-submodules requests ^
  --collect-submodules tqdm ^
  --collect-submodules multiprocessing ^
  --collect-submodules customtkinter ^
  --hidden-import scanner ^
  --hidden-import pypdf ^
  --hidden-import docx ^
  --hidden-import rarfile ^
  --hidden-import _socket ^
  --hidden-import socket ^
  --hidden-import ssl ^
  --hidden-import _ssl ^
  --hidden-import select ^
  --hidden-import _queue ^
  --clean ^
  --noconfirm ^
  forensic_agent_gui.py

REM === 2) CLI .exe ===========================================================
echo  Building CLI binary (forensic-agent-windows.exe) ...
pyinstaller ^
  --onefile ^
  --name forensic-agent-windows ^
  --collect-submodules click ^
  --collect-submodules requests ^
  --collect-submodules tqdm ^
  --collect-submodules multiprocessing ^
  --hidden-import scanner ^
  --hidden-import pypdf ^
  --hidden-import docx ^
  --hidden-import rarfile ^
  --hidden-import _socket ^
  --hidden-import socket ^
  --hidden-import ssl ^
  --hidden-import _ssl ^
  --hidden-import select ^
  --hidden-import _queue ^
  --clean ^
  --noconfirm ^
  forensic_agent.py

if not exist "..\backend\static\downloads" mkdir "..\backend\static\downloads"

echo  Copying binaries to backend\static\downloads ...
if exist dist\ForensicAgent.exe copy /Y dist\ForensicAgent.exe ..\backend\static\downloads\ForensicAgent-windows.exe
if exist dist\forensic-agent-windows.exe copy /Y dist\forensic-agent-windows.exe ..\backend\static\downloads\forensic-agent-windows.exe

REM Strip the Mark-of-the-Web (Zone.Identifier stream) added by the browser
REM when the source was downloaded from a zip. Doesn't bypass SmartScreen
REM (that needs a paid code-signing cert) but cleans up LAN/internal copies.
powershell -NoProfile -Command ^
  "Get-ChildItem '..\backend\static\downloads\*.exe' | ForEach-Object { Unblock-File -Path $_.FullName }"

echo  Packing source archive ...
powershell -NoProfile -Command ^
  "Compress-Archive -Force -Path ../agent/forensic_agent.py, ../agent/forensic_agent_gui.py, ../agent/gui.py, ../agent/scanner.py, ../agent/setup.py, ../agent/requirements.txt, ../agent/README.md -DestinationPath ../backend/static/downloads/forensic-agent-source.zip"

echo.
echo ═══════════════════════════════════════════════════════════════════
echo  Build complete.
echo ═══════════════════════════════════════════════════════════════════
echo.
echo    GUI app:       dist\ForensicAgent.exe
echo    GUI published: ..\backend\static\downloads\ForensicAgent-windows.exe
echo    CLI published: ..\backend\static\downloads\forensic-agent-windows.exe
echo.
echo  Next steps:
echo    1. Test the .exe:       dist\ForensicAgent.exe
echo    2. Stage and commit:    git add ..\backend\static\downloads\*.exe
echo                            git commit -m "Publish Windows agent binaries"
echo                            git push
echo    3. Render auto-deploys in ~2 min.
echo    4. Verify:              https://forensic-site.onrender.com/api/agent/download/windows
echo.
