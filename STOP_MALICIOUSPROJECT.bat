@echo off
setlocal EnableExtensions
title Stop MalwareGuard server
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\stop_server.ps1"
echo.
pause
