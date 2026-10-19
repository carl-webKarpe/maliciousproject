# Starts PHP's built-in web server for MalwareGuard and records its process ID
# in runtime\server.pid so STOP_MALICIOUSPROJECT.bat stops only this process.
# Called by START_MALICIOUSPROJECT.bat; not meant to be run directly.
param(
    [Parameter(Mandatory = $true)][string]$Php,
    [Parameter(Mandatory = $true)][string]$ListenHost,
    [Parameter(Mandatory = $true)][int]$Port
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $root "runtime"
$pidFile = Join-Path $runtime "server.pid"
$logFile = Join-Path $runtime "server.log"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null

$arguments = @(
    "-d", "upload_max_filesize=55M",
    "-d", "post_max_size=60M",
    "-d", "max_execution_time=120",
    "-d", "expose_php=Off",
    "-S", "${ListenHost}:${Port}",
    "-t", "`"$root`"",
    "`"$(Join-Path $root 'router.php')`""
)

$process = Start-Process -FilePath $Php -ArgumentList $arguments -WorkingDirectory $root `
    -NoNewWindow -PassThru -RedirectStandardError $logFile
# PID plus start time: a reused PID belonging to another program never matches.
"$($process.Id)|$($process.StartTime.ToString('o'))" | Set-Content -Path $pidFile -Encoding ascii

$healthHost = if ($ListenHost -eq "0.0.0.0") { "127.0.0.1" } else { $ListenHost }
$healthy = $false
for ($i = 0; $i -lt 20 -and -not $process.HasExited; $i++) {
    Start-Sleep -Milliseconds 500
    try {
        $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri "http://${healthHost}:${Port}/api/health.php"
        if ($response.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
}

if ($process.HasExited) {
    Write-Host "[FAIL]  The PHP server stopped immediately. Details:" -ForegroundColor Red
    Get-Content $logFile -Tail 20 -ErrorAction SilentlyContinue
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host ""
if ($healthy) {
    Write-Host "[OK]    MalwareGuard is running (PID $($process.Id))." -ForegroundColor Green
} else {
    Write-Host "[WARN]  The server started but /api/health.php did not report healthy. Check runtime\server.log." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Dashboard on this PC : http://${healthHost}:${Port}/"
if ($ListenHost -ne "127.0.0.1") {
    $addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.PrefixOrigin -ne "WellKnown" }
    foreach ($address in $addresses) {
        if ($ListenHost -eq "0.0.0.0" -or $ListenHost -eq $address.IPAddress) {
            Write-Host "  Agents / other PCs   : http://$($address.IPAddress):${Port}/   ($($address.InterfaceAlias))"
        }
    }
    Write-Host ""
    Write-Host "  If other PCs cannot connect, allow the port once in an Administrator PowerShell:"
    Write-Host "    New-NetFirewallRule -DisplayName 'MalwareGuard $Port' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private"
}
Write-Host ""
Write-Host "  Keep this window open. Press Ctrl+C here or run STOP_MALICIOUSPROJECT.bat to stop."
Write-Host "  Request log: runtime\server.log"
Write-Host ""

try {
    Wait-Process -Id $process.Id
} finally {
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    Write-Host "MalwareGuard server stopped."
}
