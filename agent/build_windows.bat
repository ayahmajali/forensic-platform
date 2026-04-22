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
REM
REM Optional (needed for the "Analyze Disk Image" feature):
REM   - Sleuth Kit Windows binaries (mmls.exe, fls.exe, fsstat.exe,
REM     tsk_recover.exe, icat.exe) dropped into agent\vendor\tsk\.
REM     Download from https://www.sleuthkit.org/sleuthkit/download.php
REM     and unzip the bin\*.exe + *.dll files into agent\vendor\tsk\.
REM     If the folder is empty the build still succeeds, but disk-image
REM     analysis will be disabled at runtime.

setlocal EnableDelayedExpansion
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

REM --- Pre-flight: vendored Sleuth Kit binaries --------------------------------
REM We check for the three tools tsk_runner.py actually requires. Missing is
REM survivable (build continues) — we just warn the user that disk-image
REM analysis won't be available from the resulting .exe.
set "TSK_STATUS=present"
for %%F in (mmls.exe fls.exe tsk_recover.exe) do (
  if not exist "vendor\tsk\%%F" set "TSK_STATUS=missing"
)
if "!TSK_STATUS!"=="missing" (
  echo.
  echo [WARN]  No Sleuth Kit binaries found in agent\vendor\tsk\.
  echo         The .exe will still build but disk-image mode will be disabled.
  echo         To fix: download Sleuth Kit from
  echo            https://www.sleuthkit.org/sleuthkit/download.php
  echo         and copy bin\*.exe and bin\*.dll into agent\vendor\tsk\.
  echo.
) else (
  echo  Found Sleuth Kit binaries in vendor\tsk — they will be bundled.
)

REM Build up --add-binary flags for whatever is actually present so the
REM build works even if vendor\tsk has only a README today. PyInstaller's
REM Windows separator between src and dest is ';'.
set "TSK_BIN_ARGS="
if exist "vendor\tsk" (
  for %%F in (vendor\tsk\*.exe vendor\tsk\*.dll) do (
    set "TSK_BIN_ARGS=!TSK_BIN_ARGS! --add-binary ^"%%F;tsk^""
  )
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
  --hidden-import tsk_runner ^
  --hidden-import pypdf ^
  --hidden-import docx ^
  --hidden-import rarfile ^
  --hidden-import _socket ^
  --hidden-import socket ^
  --hidden-import ssl ^
  --hidden-import _ssl ^
  --hidden-import select ^
  --hidden-import _queue ^
  !TSK_BIN_ARGS! ^
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
  --hidden-import tsk_runner ^
  --hidden-import pypdf ^
  --hidden-import docx ^
  --hidden-import rarfile ^
  --hidden-import _socket ^
  --hidden-import socket ^
  --hidden-import ssl ^
  --hidden-import _ssl ^
  --hidden-import select ^
  --hidden-import _queue ^
  !TSK_BIN_ARGS! ^
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
  "Compress-Archive -Force -Path ../agent/forensic_agent.py, ../agent/forensic_agent_gui.py, ../agent/gui.py, ../agent/scanner.py, ../agent/tsk_runner.py, ../agent/setup.py, ../agent/requirements.txt, ../agent/README.md -DestinationPath ../backend/static/downloads/forensic-agent-source.zip"

echo.
echo ═══════════════════════════════════════════════════════════════════
echo  Build complete.
echo ═══════════════════════════════════════════════════════════════════
echo.
echo    GUI app:       dist\ForensicAgent.exe
echo    GUI published: ..\backend\static\downloads\ForensicAgent-windows.exe
echo    CLI published: ..\backend\static\downloads\forensic-agent-windows.exe
if "!TSK_STATUS!"=="missing" (
  echo.
  echo    NOTE: Sleuth Kit binaries were not bundled. Disk-image analysis
  echo          will be disabled in this build. Drop the .exe/.dll files
  echo          into agent\vendor\tsk\ and re-run this script to enable.
)
echo.
echo  Next steps:
echo    1. Test the .exe:       dist\ForensicAgent.exe
echo    2. Stage and commit:    git add ..\backend\static\downloads\*.exe
echo                            git commit -m "Publish Windows agent binaries"
echo                            git push
echo    3. Render auto-deploys in ~2 min.
echo    4. Verify:              https://forensic-platform-sy5q.onrender.com/api/agent/download/windows
echo.
