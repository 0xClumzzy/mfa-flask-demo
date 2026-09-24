@echo off
setlocal
cd /d "%~dp0"
title Flask MFA Demo

echo ============================================
echo   Flask MFA Demo - setup and start
echo ============================================
echo.

set "PYEXE="
python --version >nul 2>nul
if not errorlevel 1 set "PYEXE=python"

if not defined PYEXE (
  py -3 --version >nul 2>nul
  if not errorlevel 1 set "PYEXE=py -3"
)

if not defined PYEXE (
  echo [ERROR] Python not found.
  echo.
  echo 1. Go to https://www.python.org/downloads/
  echo 2. Install Python 3
  echo 3. IMPORTANT: tick "Add python.exe to PATH" on the first installer screen
  echo 4. Close this window and double-click start.bat again
  echo.
  pause
  exit /b 1
)

echo [1/3] Python found. Creating virtual environment...
if not exist ".venv\Scripts\python.exe" (
  %PYEXE% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Could not create venv.
    pause
    exit /b 1
  )
)

echo [2/3] Installing packages (needs internet once)...
".venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo [ERROR] pip install failed. Check internet connection and retry.
  pause
  exit /b 1
)

echo [3/3] Starting server - browser opens automatically...
echo       Keep this window open. Close it to stop the server.
echo.
".venv\Scripts\python.exe" app.py

echo.
echo Server stopped.
pause
