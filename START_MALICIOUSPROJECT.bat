@echo off
setlocal EnableExtensions
title MalwareGuard server
cd /d "%~dp0"

echo.
echo  MalwareGuard server
echo  ===================
echo.

rem --- 1. PHP --------------------------------------------------------------
rem Use MALWAREGUARD_PHP to point at a specific php.exe; otherwise PATH, then C:\php.
set "PHP_EXE="
if defined MALWAREGUARD_PHP set "PHP_EXE=%MALWAREGUARD_PHP%"
if not defined PHP_EXE for /f "delims=" %%P in ('where php 2^>nul') do if not defined PHP_EXE set "PHP_EXE=%%P"
if not defined PHP_EXE if exist "C:\php\php.exe" set "PHP_EXE=C:\php\php.exe"
if not defined PHP_EXE (
    echo [FAIL]  PHP was not found. Install PHP 8.1+ for Windows ^(https://windows.php.net/download^),
    echo         add its folder to PATH, or set MALWAREGUARD_PHP to the full path of php.exe.
    goto :failed
)
"%PHP_EXE%" -v >nul 2>&1 || (
    echo [FAIL]  "%PHP_EXE%" could not be started.
    goto :failed
)

rem --- 2. Python (only needed on computers that run the agent) -----------------
set "PY_FOUND="
where py >nul 2>&1 && set "PY_FOUND=1"
where python >nul 2>&1 && set "PY_FOUND=1"
if defined PY_FOUND (echo [OK]    Python found ^(needed only for the agent^)) else (echo [INFO]  Python not found. The server does not need it; agent PCs do.)

rem --- 3. MySQL Server service ---------------------------------------------
for /f "usebackq delims=" %%S in (`powershell -NoProfile -Command "$s = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'MySQL*' -or $_.DisplayName -like 'MySQL*' }; if (-not $s) { 'NONE' } elseif ($s | Where-Object Status -eq 'Running') { 'RUNNING ' + (($s | Where-Object Status -eq 'Running').Name -join ',') } else { 'STOPPED ' + ($s.Name -join ',') }"`) do set "MYSQL_STATE=%%S"
if "%MYSQL_STATE:~0,7%"=="RUNNING" echo [OK]    MySQL service running ^(%MYSQL_STATE:~8%^)
rem A stopped MySQL80 is fine when XAMPP's MySQL/MariaDB is used instead; the
rem database connection check below decides.
if "%MYSQL_STATE:~0,7%"=="STOPPED" (
    echo [INFO]  The MySQL service ^(%MYSQL_STATE:~8%^) is stopped. Fine if you use XAMPP's MySQL; otherwise start it in services.msc.
)
if "%MYSQL_STATE%"=="NONE" echo [INFO]  No local MySQL service found. Continuing in case DB_HOST points to another computer.

rem --- 4-6. Configuration, packages, database connection, port ---------------
"%PHP_EXE%" tools\preflight.php || goto :failed

rem --- Database schema (creates missing tables, applies pending migrations) ---
"%PHP_EXE%" database_setup.php || goto :failed

for /f "usebackq tokens=1,* delims==" %%A in (`"%PHP_EXE%" tools\preflight.php --print-env`) do set "%%A=%%B"

rem --- 7-11. Start the web server and keep it running ------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\run_server.ps1" -Php "%PHP_EXE%" -ListenHost "%APP_HOST%" -Port %APP_PORT%
echo.
pause
exit /b 0

:failed
echo.
echo  MalwareGuard did not start. Fix the problem above and run this file again.
echo.
pause
exit /b 1
