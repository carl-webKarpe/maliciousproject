@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [FAIL]  The agent is not installed yet. Run INSTALL_AGENT.bat first.
    pause
    exit /b 1
)

rem START_AGENT.bat --background is used by the sign-in scheduled task: no window,
rem output goes to data\logs\agent.log only.
if /i "%~1"=="--background" (
    start "" /b ".venv\Scripts\pythonw.exe" agent.py run --quiet
    exit /b 0
)

title MalwareGuard agent
echo MalwareGuard agent - close this window, press Ctrl+C, or run STOP_AGENT.bat to stop.
echo Log file: %~dp0data\logs\agent.log
echo.
".venv\Scripts\python.exe" agent.py run
echo.
pause
