# Stops the PHP server started by START_MALICIOUSPROJECT.bat, and nothing else.
# The process must match the PID *and* start time recorded in runtime\server.pid
# and must be php running this project's router.php.

$root = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $root "runtime\server.pid"

if (-not (Test-Path $pidFile)) {
    Write-Host "[INFO]  MalwareGuard server is not running (no runtime\server.pid)."
    exit 0
}

$parts = (Get-Content $pidFile -Raw).Trim().Split("|")
$serverPid = [int]$parts[0]
$recordedStart = if ($parts.Count -gt 1) { [datetime]::Parse($parts[1]) } else { $null }

$process = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Host "[INFO]  The recorded server process ($serverPid) is no longer running. Cleaning up."
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    exit 0
}

$details = Get-CimInstance Win32_Process -Filter "ProcessId = $serverPid" -ErrorAction SilentlyContinue
$commandLine = if ($details) { [string]$details.CommandLine } else { "" }
$sameStart = $recordedStart -and ([math]::Abs(($process.StartTime - $recordedStart).TotalSeconds) -lt 2)
$isOurs = $process.ProcessName -like "php*" -and $commandLine -like "*router.php*" -and $commandLine -like "*-S*" -and $sameStart

if (-not $isOurs) {
    Write-Host "[WARN]  PID $serverPid now belongs to another program ($($process.ProcessName)). It was NOT stopped." -ForegroundColor Yellow
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    exit 1
}

Stop-Process -Id $serverPid
Remove-Item $pidFile -ErrorAction SilentlyContinue
Write-Host "[OK]    MalwareGuard server (PID $serverPid) stopped. Other PHP and Python programs were left running." -ForegroundColor Green
