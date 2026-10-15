@echo off
setlocal
cd /d "%~dp0"

echo.
echo ==============================================
echo          OmniShield AI - Local Preview
echo ==============================================
echo.

where py >nul 2>nul
if errorlevel 1 (
  echo ERROR: Python was not found.
  echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/
  echo During installation, enable "Add Python to PATH", then run this file again.
  pause
  exit /b 1
)

if not exist "omnishield-backend\.venv\Scripts\python.exe" (
  echo [1/4] Creating Python virtual environment...
  py -3 -m venv "omnishield-backend\.venv"
  if errorlevel 1 goto :failed
)

echo [2/4] Installing backend requirements (first run may take a few minutes)...
"omnishield-backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :failed
"omnishield-backend\.venv\Scripts\python.exe" -m pip install -r "omnishield-backend\requirements.txt"
if errorlevel 1 goto :failed

if not exist "omnishield-backend\.env" (
  echo [3/4] Creating local development configuration...
  copy "omnishield-backend\.env.example" "omnishield-backend\.env" >nul
)

echo [4/4] Starting local API server...
start "OmniShield AI Backend" cmd /k "cd /d ""%~dp0omnishield-backend"" ^&^& ""%~dp0omnishield-backend\.venv\Scripts\python.exe"" -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
echo Waiting a few seconds for the server to start...
timeout /t 5 /nobreak >nul
start "" "http://127.0.0.1:8000/demo"
echo.
echo Dashboard: http://127.0.0.1:8000/demo
echo API docs:  http://127.0.0.1:8000/docs
echo Keep the backend terminal open while using the preview.
echo To stop the server, close its terminal window or press Ctrl+C there.
echo.
pause
exit /b 0

:failed
echo.
echo Setup failed. Check the error above and see README.md for manual setup.
pause
exit /b 1
