@echo off
:: ============================================================
::  CyberX Forensics Platform — Windows One-Click Launcher
:: ============================================================

title CyberX Forensics Platform Launcher
echo ============================================================
echo   CyberX Forensics Platform - Windows Launcher
echo ============================================================
echo.

cd /d "%~dp0"

:: ── 1. Check & Start MobSF Docker Container ─────────────────
echo [1/3] Checking MobSF Docker container on port 8001...
docker ps --format "{{.Ports}}" 2>nul | findstr /C:"8001->8000" >nul
if %errorlevel% equ 0 (
    echo       [OK] MobSF Docker container is already running on port 8001.
) else (
    echo       Attempting to start MobSF Docker container...
    docker run -d -p 8001:8000 -e MOBSF_API_KEY="fixed-mobsf-api-key" opensecurity/mobile-security-framework-mobsf:latest 2>nul
    if %errorlevel% equ 0 (
        echo       [OK] MobSF Docker started on http://localhost:8001
    ) else (
        echo       [NOTE] MobSF Docker container skipped or Docker Desktop offline. Local MobSF scan engine active.
    )
)
echo.

:: ── 2. Start FastAPI Backend ─────────────────────────────────
echo [2/3] Starting FastAPI Backend API on http://localhost:8000 ...
if exist ".venv\Scripts\python.exe" (
    start "CyberX Backend" cmd /k "cd /d %~dp0backend && ..\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
) else (
    start "CyberX Backend" cmd /k "cd /d %~dp0backend && uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000"
)

:: Wait 2 seconds
timeout /t 2 >nul

:: ── 3. Start React Frontend ──────────────────────────────────
echo [3/3] Starting React Frontend UI on http://localhost:5173 ...
start "CyberX Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ============================================================
echo   Platform Services Initialized!
echo.
echo   Frontend UI : http://localhost:5173
echo   Backend API : http://localhost:8000
echo   API Docs    : http://localhost:8000/docs
echo   MobSF Server: http://localhost:8001
echo ============================================================
echo.
