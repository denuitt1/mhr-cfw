@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM -------- MasterHttpRelayVPN GUI Launcher (Windows) --------
REM Creates a local virtualenv, installs deps, then starts the GUI.
REM Certificate management is done via the GUI buttons.

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

echo [*] Installing dependencies ...
"%VPY%" -m pip install --disable-pip-version-check -q --upgrade pip >nul
"%VPY%" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
    echo [!] PyPI install failed. Retrying via runflare mirror ...
    "%VPY%" -m pip install --disable-pip-version-check -q -r requirements.txt
    if errorlevel 1 (
        echo [X] Could not install dependencies.
        pause
        exit /b 1
    )
)

REM No need for setup.py – the GUI will create config.json if missing.
REM No separate CA uninstall handling – use the GUI buttons instead.

echo.
echo [*] Starting DomainFront Tunnel GUI ...
echo.
"%VPY%" gui.py %*
set "RC=%errorlevel%"
if not "%RC%"=="0" pause
exit /b %RC%