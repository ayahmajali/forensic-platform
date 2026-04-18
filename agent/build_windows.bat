@echo off
REM build_windows.bat - Build a single-file Windows .exe for the forensic agent.
REM
REM Produces:  dist\forensic-agent-windows.exe
REM Copies to: ..\backend\static\downloads\forensic-agent-windows.exe
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
pip install pypdf python-docx rarfile || echo (optional parsers skipped)

echo  Running PyInstaller ...
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist
pyinstaller ^
  --onefile ^
  --name forensic-agent-windows ^
  --collect-submodules click ^
  --collect-submodules requests ^
  --collect-submodules tqdm ^
  --hidden-import scanner ^
  --hidden-import pypdf ^
  --hidden-import docx ^
  --hidden-import rarfile ^
  --clean ^
  --noconfirm ^
  forensic_agent.py

if not exist "..\backend\static\downloads" mkdir "..\backend\static\downloads"

echo  Copying binary to backend\static\downloads ...
copy /Y dist\forensic-agent-windows.exe ..\backend\static\downloads\forensic-agent-windows.exe

echo  Packing source archive ...
powershell -NoProfile -Command ^
  "Compress-Archive -Force -Path ../agent/forensic_agent.py, ../agent/scanner.py, ../agent/setup.py, ../agent/requirements.txt, ../agent/README.md -DestinationPath ../backend/static/downloads/forensic-agent-source.zip"

echo.
echo  Done.
echo    Binary:    dist\forensic-agent-windows.exe
echo    Published: ..\backend\static\downloads\forensic-agent-windows.exe
echo.
echo    Test it:
echo      .\dist\forensic-agent-windows.exe --help
