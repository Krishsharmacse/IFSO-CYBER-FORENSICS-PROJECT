@echo off
:: ============================================================
::  Build installer.exe from installer.py using PyInstaller
::  Run: build_installer.bat
:: ============================================================
setlocal

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo ============================================================
echo   IFSO Cyber Forensics Platform - EXE Builder
echo ============================================================
echo.

:: ── Check uv ─────────────────────────────────────────────────
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] uv is not installed. Download from https://github.com/astral-sh/uv
    pause
    exit /b 1
)
echo [OK] uv found.

:: ── Install PyInstaller ───────────────────────────────────────
echo [1/3] Installing PyInstaller...
uv pip install pyinstaller --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install PyInstaller.
    pause
    exit /b 1
)
echo       PyInstaller installed.
echo.

:: ── Compile to EXE ───────────────────────────────────────────
echo [2/3] Compiling installer.py to EXE...
uv run pyinstaller ^
    --onefile ^
    --windowed ^
    --name "IFSO_Setup" ^
    --icon NONE ^
    --clean ^
    installer.py

if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller build failed. See output above.
    pause
    exit /b 1
)
echo.
echo [3/3] Build complete!
echo.
echo   Output EXE: %SCRIPT_DIR%dist\IFSO_Setup.exe
echo.
echo   Run IFSO_Setup.exe as Administrator on any Windows machine
echo   to automatically install all required tools.
echo.
echo ============================================================

:: Open the dist folder
explorer "%SCRIPT_DIR%dist"

pause
