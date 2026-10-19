@echo off
setlocal EnableExtensions
title Stop MalwareGuard agent
cd /d "%~dp0"

if not exist "data\agent.pid" (
    echo [INFO]  The agent is not running.
    goto :end
)

rem Ask the agent to stop cleanly; it checks for this file every second.
rem Events not yet delivered stay queued and are sent on the next start.
type nul > "data\stop.request"
echo [....]  Waiting for the agent to stop...
for /l %%i in (1,1,15) do (
    if not exist "data\agent.pid" goto :stopped
    timeout /t 1 /nobreak >nul
)

rem Still running: stop only the process recorded in agent.pid, and only if it
rem really is this agent (python running agent.py from this folder).
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$agentPid = [int](Get-Content 'data\agent.pid' -Raw).Trim();" ^
  "$p = Get-CimInstance Win32_Process -Filter \"ProcessId = $agentPid\";" ^
  "if ($p -and $p.Name -like 'python*' -and $p.CommandLine -like '*agent.py*') { Stop-Process -Id $agentPid -Force; 'Agent process stopped.' }" ^
  "else { 'The recorded PID is not the agent; nothing was stopped.' }"
del /q "data\agent.pid" "data\stop.request" 2>nul

:stopped
echo [OK]    MalwareGuard agent stopped. Other Python programs were left running.

:end
echo.
pause
