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
echo  Done.
echo    GUI app:      dist\ForensicAgent.exe
echo    GUI published: ..\backend\static\downloads\ForensicAgent-windows.exe
echo    CLI published: ..\backend\static\downloads\forensic-agent-windows.exe
echo.
echo    Test it:
echo      dist\ForensicAgent.exe
