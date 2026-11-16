@echo off
setlocal EnableExtensions
title MalwareGuard agent - automatic start
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [FAIL]  The agent is not installed yet. Run INSTALL_AGENT.bat first.
    pause
    exit /b 1
)
rem Makes an already enrolled PC start the agent by itself at every sign-in.
rem No new token is needed. To turn it off: agent.py autostart off
".venv\Scripts\python.exe" agent.py autostart on
echo.
pause
