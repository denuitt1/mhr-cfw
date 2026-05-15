@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM -------- MasterHttpRelayVPN one-click launcher (Windows) --------
REM Creates a local virtualenv, installs deps, runs the setup wizard
REM if needed, then starts the proxy. Also checks and installs CA cert
REM if not already trusted.

set "VENV_DIR=.venv"
set "PY="

where py >nul 2>&1
if !errorlevel!==0 (
    set "PY=py -3"
) else (
    where python >nul 2>&1
    if !errorlevel!==0 (
        set "PY=python"
    )
)

if "%PY%"=="" (
    echo [X] Python 3.10+ was not found on PATH.
    echo     Install from https://www.python.org/downloads/ and re-run this script.
    pause
    exit /b 1
)

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [*] Creating virtual environment in %VENV_DIR% ...
    %PY% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [X] Failed to create virtualenv.
        pause
        exit /b 1
    )
)

set "VPY=%VENV_DIR%\Scripts\python.exe"



if not exist "config.json" (
    echo [*] No config.json found — launching setup wizard ...
    "%VPY%" setup.py
    if errorlevel 1 (
        echo [X] Setup cancelled.
        pause
        exit /b 1
    )
)

REM -------- Check for uninstall flag --------
echo %* | findstr /C:"--uninstall-cert" >nul
if not errorlevel 1 (
    echo [*] Uninstalling CA certificate ...
    "%VPY%" main.py --uninstall-cert
    exit /b %errorlevel%
)


echo.
echo [*] Starting mhr-cfw ...
echo.
"%VPY%" main.py %*
set "RC=%errorlevel%"
if not "%RC%"=="0" pause
exit /b %RC%