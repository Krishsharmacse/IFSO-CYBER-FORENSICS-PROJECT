@echo off
:: CyberX Forensics Platform — Windows Quick Start
:: Starts backend and frontend in separate windows

echo Starting CyberX Forensics Platform...
echo.

cd /d "%~dp0"

:: Start Backend
echo [1/2] Starting FastAPI backend on http://localhost:8000 ...
start "CyberX Backend" cmd /k "cd backend && ..\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"

:: Wait a moment
timeout /t 2 >nul

:: Start Frontend
echo [2/2] Starting React frontend on http://localhost:5173 ...
start "CyberX Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo Both services started in separate windows.
echo   Backend API : http://localhost:8000
echo   Frontend UI : http://localhost:5173
echo   API Docs    : http://localhost:8000/docs
echo   Diagnostics : http://localhost:8000/diagnostics
