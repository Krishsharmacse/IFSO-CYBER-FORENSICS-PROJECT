@echo off
:: ============================================================
::  CyberX Forensics Platform — Windows Setup Script
::  Run this once as Administrator to configure the environment
:: ============================================================

echo ============================================================
echo   CyberX Forensics Platform - Windows Setup
echo ============================================================
echo.

:: Check Python version
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download from: https://www.python.org/downloads/
    exit /b 1
)

:: Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo         Download from: https://nodejs.org/
    exit /b 1
)

echo [OK] Python and Node.js found.
echo.

:: ── Backend Python environment ────────────────────────────────
echo [1/5] Setting up Python virtual environment...

cd /d "%~dp0"

if not exist ".venv" (
    python -m venv .venv
    echo       Created .venv
) else (
    echo       .venv already exists, skipping creation.
)

call .venv\Scripts\activate.bat

echo [2/5] Installing Python dependencies...
pip install --upgrade pip --quiet
pip install ^
    fastapi uvicorn sqlalchemy python-dotenv ^
    yara-python joblib pandas scikit-learn numpy ^
    requests paramiko pyzipper pikepdf ^
    eml-parser python-evtx ^
    impacket whois ^
    androguard ^
    --quiet

echo       Python packages installed.
echo.

:: ── Frontend ──────────────────────────────────────────────────
echo [3/5] Installing frontend Node.js dependencies...
cd frontend
npm install --silent
cd ..
echo       Frontend packages installed.
echo.

:: ── External tools check ─────────────────────────────────────
echo [4/5] Checking external tools (optional but recommended)...
echo.

:: ExifTool
exiftool -ver >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      exiftool
) else (
    echo   [MISSING] exiftool — Download: https://exiftool.org
    echo             Extract exiftool(-k).exe, rename to exiftool.exe, add to PATH
)

:: tshark
tshark -v >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      tshark (Wireshark)
) else (
    echo   [MISSING] tshark — Download Wireshark: https://www.wireshark.org
    echo             Ensure tshark is included in the Wireshark installation
)

:: John the Ripper
john >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      john (John the Ripper)
) else (
    echo   [MISSING] john — Download: https://www.openwall.com/john/
    echo             Extract and add the run\ folder to PATH
)

:: Volatility
vol --help >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      volatility3 (vol)
) else (
    echo   [MISSING] volatility3 — Run: pip install volatility3
)

:: Steghide
steghide --version >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      steghide
) else (
    echo   [MISSING] steghide — Download: https://steghide.sourceforge.net
    echo             Add the folder containing steghide.exe to PATH
)

:: Ghidra
if exist "plugins\ghidra_*\support\analyzeHeadless.bat" (
    echo   [OK]      Ghidra (plugins folder)
) else (
    echo   [MISSING] Ghidra — Download: https://ghidra-sre.org
    echo             Extract to plugins\ghidra_X.Y.Z_PUBLIC\
)

:: Sleuth Kit
mmls >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK]      SleuthKit (mmls, fls, fsstat)
) else (
    echo   [MISSING] SleuthKit — Download: https://www.sleuthkit.org/sleuthkit/download.php
    echo             Add the bin\ folder to PATH
)

echo.
echo [5/5] Checking .env file...
if not exist "backend\.env" (
    copy "backend\.env.example" "backend\.env" >nul 2>&1
    echo   Created backend\.env from .env.example (add your API keys there)
) else (
    echo   backend\.env already exists.
)

echo.
echo ============================================================
echo   Setup complete!
echo.
echo   To start the platform:
echo     Backend : cd backend ^&^& ..\venv\Scripts\activate ^&^& uvicorn main:app --reload
echo     Frontend: cd frontend ^&^& npm run dev
echo.
echo   Or use the run_windows.bat shortcut.
echo ============================================================
