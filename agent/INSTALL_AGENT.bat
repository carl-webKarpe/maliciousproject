@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Server address offered by default (press Enter to accept it).
rem XAMPP/Apache: http://IP/MaliciousProject   Built-in server: http://IP:8000
set "DEFAULT_SERVER=http://10.83.54.4/MaliciousProject"
title Install MalwareGuard agent
cd /d "%~dp0"

echo.
echo  MalwareGuard agent setup
echo  ========================
echo  Install this only on computers you own or are authorized to monitor.
echo  The agent reports file activity in approved folders (default: Downloads)
echo  to your MalwareGuard server. It never runs, deletes or moves files.
echo.

rem --- Python 3.8+ ----------------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
    echo [FAIL]  Python 3 was not found. Install it from https://www.python.org/downloads/windows/
    echo         and tick "Add python.exe to PATH" during installation, then run this file again.
    goto :failed
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" || (
    echo [FAIL]  Python 3.8 or newer is required.
    goto :failed
)
echo [OK]    Python found

rem --- Private environment with the agent's dependencies ---------------------
rem A .venv copied from another computer points at that computer's Python
rem and cannot run here; rebuild it.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys" >nul 2>&1 || (
        echo [....]  agent\.venv was made on another computer; rebuilding it for this one.
        rmdir /s /q ".venv"
    )
)
if not exist ".venv\Scripts\python.exe" (
    echo [....]  Creating the agent's Python environment in agent\.venv
    %PY% -m venv .venv || (echo [FAIL]  Could not create the virtual environment. & goto :failed)
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt || (
    echo [FAIL]  Installing dependencies failed. Check the internet connection and try again.
    goto :failed
)
echo [OK]    Dependencies installed ^(requests, watchdog^)

if not exist "data" mkdir "data"
if not exist "data\agent_config.json" copy /y "agent_config.example.json" "data\agent_config.json" >nul

rem --- Enrollment ------------------------------------------------------------
set "ENROLL=Y"
if exist "data\credential.dat" (
    echo.
    echo This computer is already enrolled.
    set /p "ENROLL=Enroll it again with a new token? (y/N): "
    if /i not "!ENROLL!"=="y" set "ENROLL=N"
)

if /i "%ENROLL%"=="Y" (
    echo.
    echo Ask your administrator for the server address and a one-time enrollment token
    echo ^(dashboard: Devices ^> Enrollment tokens ^> Generate token^).
    echo.
    set "SERVER="
    set /p "SERVER=Server address [!DEFAULT_SERVER!] : "
    if "!SERVER!"=="" set "SERVER=!DEFAULT_SERVER!"
    set /p "TOKEN=Enrollment token : "
    set /p "NAME=Name for this computer [%COMPUTERNAME%] : "
    if "!NAME!"=="" set "NAME=%COMPUTERNAME%"
    ".venv\Scripts\python.exe" agent.py enroll --server "!SERVER!" --token "!TOKEN!" --name "!NAME!" || goto :failed
)

echo.
echo [....]  Checking the connection to the server
".venv\Scripts\python.exe" agent.py check
echo.
echo Approved folders are listed under "watch_directories" in:
echo     %~dp0data\agent_config.json
echo {DOWNLOADS} means this user's Downloads folder. Edit the file to add an
echo administrator-approved folder, then restart the agent.
echo.

rem --- Optional: start automatically at sign-in ----------------------------------
set "AUTO=N"
set /p "AUTO=Start the agent automatically when this user signs in? (y/N): "
if /i "%AUTO%"=="y" (
    schtasks /create /tn "MalwareGuard Agent" /tr "\"%~dp0START_AGENT.bat\" --background" /sc onlogon /rl limited /f >nul && (
        echo [OK]    Scheduled task "MalwareGuard Agent" created. Remove it with:
        echo         schtasks /delete /tn "MalwareGuard Agent" /f
    ) || echo [WARN]  Could not create the scheduled task. You can still start the agent with START_AGENT.bat.
)

set "NOW=Y"
set /p "NOW=Start the agent now? (Y/n): "
if /i not "%NOW%"=="n" start "MalwareGuard agent" "%~dp0START_AGENT.bat"

echo.
echo Setup finished.
pause
exit /b 0

:failed
echo.
echo Setup did not finish. Fix the problem above and run INSTALL_AGENT.bat again.
pause
exit /b 1
