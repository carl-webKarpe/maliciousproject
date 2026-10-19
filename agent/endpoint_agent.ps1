param(
    [string]$ApiUrl = "http://localhost:8000/api/agent.php",
    [string]$Token = "",
    [int]$IntervalSeconds = 30
)

$resolvedToken = if ($Token) { $Token } elseif ($env:ENDPOINT_AGENT_TOKEN) { $env:ENDPOINT_AGENT_TOKEN } else { "demo-endpoint-token" }

function Invoke-AgentRequest {
    param(
        [hashtable]$Payload
    )

    $jsonBody = $Payload | ConvertTo-Json -Depth 10
    $headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
        "X-Agent-Token" = $resolvedToken
    }

    try {
        return Invoke-RestMethod -Uri $ApiUrl -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
    }
    catch {
        $errorMessage = $_.Exception.Message
        return [pscustomobject]@{
            status = "error"
            message = $errorMessage
        }
    }
}

function Get-AgentMeta {
    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue

    $deviceIdSource = if ($bios -and $bios.SerialNumber) { $bios.SerialNumber } else { $computerSystem.Name }
    $hostname = [System.Net.Dns]::GetHostName()
    $username = $env:USERNAME
    $osName = if ($osInfo -and $osInfo.Caption) { $osInfo.Caption.Trim() } else { "Windows" }
    $sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $seenAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    return [pscustomobject]@{
        device_id = $deviceIdSource
        hostname = $hostname
        username = $username
        os_name = $osName
        session_id = $sessionId
        seen_at = $seenAt
    }
}

function Get-ProcessSnapshot {
    $seenAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $rows = @()

    $processes = Get-Process | Where-Object { $_.ProcessName -and $_.Id -gt 0 } | Sort-Object CPU -Descending | Select-Object -First 15
    foreach ($process in $processes) {
        $windowTitle = ""
        try {
            $windowTitle = (Get-Process -Id $process.Id -ErrorAction SilentlyContinue).MainWindowTitle
        }
        catch {
            $windowTitle = ""
        }

        $rows += [pscustomobject]@{
            name = $process.ProcessName
            pid = [int]$process.Id
            cpu_percent = [math]::Round([double]$process.CPU, 2)
            memory_mb = [math]::Round([double]($process.WorkingSet64 / 1MB), 2)
            window_title = $windowTitle
            status = "running"
            seen_at = $seenAt
        }
    }

    return $rows
}

function Get-EndpointDetections {
    $writableRoots = @(
        $env:TEMP,
        (Join-Path $env:USERPROFILE "Downloads"),
        $env:PUBLIC
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $normalizedRoots = @($writableRoots | ForEach-Object {
        [System.IO.Path]::GetFullPath($_).TrimEnd('\') + '\'
    })
    $detections = @()
    $runningProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue

    foreach ($process in $runningProcesses) {
        $path = [string]$process.ExecutablePath
        if (-not $path) { continue }

        try {
            $fullPath = [System.IO.Path]::GetFullPath($path)
        }
        catch {
            continue
        }

        $inWritableLocation = $false
        foreach ($root in $normalizedRoots) {
            if ($fullPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                $inWritableLocation = $true
                break
            }
        }

        if (-not $inWritableLocation) { continue }

        $signature = Get-AuthenticodeSignature -LiteralPath $fullPath -ErrorAction SilentlyContinue
        $signatureStatus = if ($null -ne $signature) { $signature.Status.ToString() } else { "Unavailable" }
        if ($signatureStatus -eq "Valid") { continue }

        $severity = if ($signatureStatus -in @("HashMismatch", "NotTrusted")) { "high" } else { "medium" }
        $processName = [System.IO.Path]::GetFileName($fullPath)
        $detections += [pscustomobject]@{
            type = "untrusted_user_writable_executable"
            severity = $severity
            message = "Review executable '$processName' (PID $($process.ProcessId)) running from '$fullPath'; signature status: $signatureStatus. This heuristic is not a malware verdict."
        }
    }

    return $detections
}

Write-Host "Starting MalwareGuard endpoint agent..."
Write-Host "Target: $ApiUrl"
Write-Host "Token: $resolvedToken"

$meta = Get-AgentMeta
$registerResponse = Invoke-AgentRequest @{
    action = "register"
    device_id = $meta.device_id
    hostname = $meta.hostname
    username = $meta.username
    os_name = $meta.os_name
    seen_at = $meta.seen_at
}

$registerStatus = if ($null -ne $registerResponse.status) { $registerResponse.status } else { "ok" }
Write-Host ("Register: " + $registerStatus)

while ($true) {
    $meta = Get-AgentMeta
    $heartbeatResponse = Invoke-AgentRequest @{
        action = "heartbeat"
        device_id = $meta.device_id
        session_id = $meta.session_id
        username = $meta.username
        active_window = "Desktop"
        cpu_percent = 0
        memory_mb = 0
        network_status = "online"
        seen_at = $meta.seen_at
    }

    $processes = Get-ProcessSnapshot
    $processResponse = Invoke-AgentRequest @{
        action = "processes"
        device_id = $meta.device_id
        seen_at = $meta.seen_at
        processes = $processes
    }

    $detections = Get-EndpointDetections
    $alertResponse = Invoke-AgentRequest @{
        action = "alerts"
        device_id = $meta.device_id
        alerts = @($detections)
    }

    $heartbeatStatus = if ($null -ne $heartbeatResponse.status) { $heartbeatResponse.status } else { "ok" }
    $processStatus = if ($null -ne $processResponse.status) { $processResponse.status } else { "ok" }
    $alertStatus = if ($null -ne $alertResponse.status) { $alertResponse.status } else { "ok" }

    Write-Host ("Heartbeat: " + $heartbeatStatus)
    Write-Host ("Processes: " + $processStatus)
    Write-Host ("Detections: " + $alertStatus + " (" + $detections.Count + " found)")

    Start-Sleep -Seconds $IntervalSeconds
}
