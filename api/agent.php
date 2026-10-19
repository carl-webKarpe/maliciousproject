<?php

header("Content-Type: application/json");

require_once __DIR__ . "/../app_config.php";
require_once __DIR__ . "/../db.php";

function sendJson(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$expectedToken = (string) malwareGuardSetting("ENDPOINT_AGENT_TOKEN", "");
$providedToken = $_SERVER["HTTP_X_AGENT_TOKEN"] ?? $_SERVER["HTTP_X_ENDPOINT_AGENT_TOKEN"] ?? "";

if ($expectedToken === "") {
    sendJson(503, [
        "status" => "disabled",
        "message" => "Endpoint agent support is not enabled. Set ENDPOINT_AGENT_TOKEN in .env."
    ]);
}

if (!hash_equals($expectedToken, (string) $providedToken)) {
    sendJson(401, [
        "status" => "unauthorized",
        "message" => "Invalid agent token."
    ]);
}

$rawJson = file_get_contents("php://input");
$payload = json_decode($rawJson ?: "{}", true);
if (!is_array($payload)) {
    sendJson(400, [
        "status" => "error",
        "message" => "Request body must be valid JSON."
    ]);
}

$action = trim((string) ($payload["action"] ?? ""));
if ($action === "") {
    sendJson(400, [
        "status" => "error",
        "message" => "Missing action."
    ]);
}

$deviceId = trim((string) ($payload["device_id"] ?? ""));
if ($deviceId === "") {
    sendJson(400, [
        "status" => "error",
        "message" => "Missing device_id."
    ]);
}

$deviceName = trim((string) ($payload["hostname"] ?? $payload["device_name"] ?? ""));
$username = trim((string) ($payload["username"] ?? ""));
$osName = trim((string) ($payload["os_name"] ?? ""));
$sessionId = trim((string) ($payload["session_id"] ?? ""));
$activeWindow = trim((string) ($payload["active_window"] ?? ""));
$cpuPercent = (float) ($payload["cpu_percent"] ?? 0);
$memoryMb = (float) ($payload["memory_mb"] ?? 0);
$networkStatus = trim((string) ($payload["network_status"] ?? "unknown"));
$seenAt = trim((string) ($payload["seen_at"] ?? date("Y-m-d H:i:s")));

if ($action === "register") {
    $stmt = $conn->prepare(
        "INSERT INTO endpoint_devices (device_id, hostname, username, os_name, last_seen_at)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
             hostname = VALUES(hostname),
             username = VALUES(username),
             os_name = VALUES(os_name),
             last_seen_at = VALUES(last_seen_at)"
    );

    if (!$stmt) {
        sendJson(500, [
            "status" => "error",
            "message" => "Database error: " . $conn->error
        ]);
    }

    $stmt->bind_param("sssss", $deviceId, $deviceName, $username, $osName, $seenAt);
    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        sendJson(500, [
            "status" => "error",
            "message" => "Failed to register endpoint device."
        ]);
    }

    sendJson(200, [
        "status" => "ok",
        "device_id" => $deviceId,
        "message" => "Endpoint registered."
    ]);
}

if ($action === "heartbeat") {
    if ($sessionId === "") {
        sendJson(400, [
            "status" => "error",
            "message" => "Missing session_id."
        ]);
    }

    $stmt = $conn->prepare(
        "INSERT INTO endpoint_sessions (device_id, session_id, user_name, active_window, cpu_percent, memory_mb, network_status, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        sendJson(500, [
            "status" => "error",
            "message" => "Database error: " . $conn->error
        ]);
    }

    $stmt->bind_param("ssssddss", $deviceId, $sessionId, $username, $activeWindow, $cpuPercent, $memoryMb, $networkStatus, $seenAt);
    $ok = $stmt->execute();
    $stmt->close();

    if (!$ok) {
        sendJson(500, [
            "status" => "error",
            "message" => "Failed to store endpoint heartbeat."
        ]);
    }

    $upd = $conn->prepare("UPDATE endpoint_devices SET last_seen_at = ? WHERE device_id = ?");
    $upd->bind_param("ss", $seenAt, $deviceId);
    $upd->execute();
    $upd->close();

    sendJson(200, [
        "status" => "ok",
        "device_id" => $deviceId,
        "session_id" => $sessionId,
        "message" => "Heartbeat accepted."
    ]);
}

if ($action === "processes") {
    $processes = $payload["processes"] ?? [];
    if (!is_array($processes)) {
        sendJson(400, [
            "status" => "error",
            "message" => "Missing process list."
        ]);
    }

    $inserted = 0;
    $stmt = $conn->prepare(
        "INSERT INTO endpoint_processes (device_id, process_name, process_id, cpu_percent, memory_mb, window_title, status, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );

    if (!$stmt) {
        sendJson(500, [
            "status" => "error",
            "message" => "Database error: " . $conn->error
        ]);
    }

    foreach ($processes as $process) {
        if (!is_array($process)) {
            continue;
        }

        $name = trim((string) ($process["name"] ?? $process["process_name"] ?? "unknown"));
        $pid = (int) ($process["pid"] ?? $process["process_id"] ?? 0);
        $pCpu = (float) ($process["cpu_percent"] ?? 0);
        $pMemory = (float) ($process["memory_mb"] ?? 0);
        $title = trim((string) ($process["window_title"] ?? ""));
        $status = trim((string) ($process["status"] ?? "running"));
        $processSeenAt = trim((string) ($process["seen_at"] ?? $seenAt));

        $stmt->bind_param("ssiddsss", $deviceId, $name, $pid, $pCpu, $pMemory, $title, $status, $processSeenAt);
        if ($stmt->execute()) {
            $inserted++;
        }
    }

    $stmt->close();

    sendJson(200, [
        "status" => "ok",
        "device_id" => $deviceId,
        "inserted" => $inserted,
        "message" => "Process snapshot received."
    ]);
}

if ($action === "alerts") {
    $alerts = $payload["alerts"] ?? [];
    if (!is_array($alerts)) {
        sendJson(400, [
            "status" => "error",
            "message" => "Alert list must be an array."
        ]);
    }

    $inserted = 0;
    $duplicates = 0;
    $check = $conn->prepare(
        "SELECT id FROM endpoint_alerts
         WHERE device_id = ? AND alert_type = ? AND message = ? AND status = 'open'
           AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
         LIMIT 1"
    );
    $insert = $conn->prepare(
        "INSERT INTO endpoint_alerts (device_id, alert_type, severity, message)
         VALUES (?, ?, ?, ?)"
    );

    if (!$check || !$insert) {
        sendJson(500, [
            "status" => "error",
            "message" => "Database error while preparing endpoint alert storage."
        ]);
    }

    foreach (array_slice($alerts, 0, 100) as $alert) {
        if (!is_array($alert)) {
            continue;
        }

        $type = trim((string) ($alert["type"] ?? ""));
        $severity = strtolower(trim((string) ($alert["severity"] ?? "medium")));
        $message = trim((string) ($alert["message"] ?? ""));

        if (
            !preg_match('/^[a-z0-9_]{1,64}$/', $type) ||
            !in_array($severity, ["low", "medium", "high", "critical"], true) ||
            $message === ""
        ) {
            continue;
        }

        $message = substr($message, 0, 2000);
        $check->bind_param("sss", $deviceId, $type, $message);
        $check->execute();
        if ($check->get_result()->num_rows > 0) {
            $duplicates++;
            continue;
        }

        $insert->bind_param("ssss", $deviceId, $type, $severity, $message);
        if ($insert->execute()) {
            $inserted++;
        }
    }

    $check->close();
    $insert->close();

    sendJson(200, [
        "status" => "ok",
        "device_id" => $deviceId,
        "inserted" => $inserted,
        "duplicates" => $duplicates,
        "message" => "Endpoint detections processed."
    ]);
}

sendJson(400, [
    "status" => "error",
    "message" => "Unsupported action: " . $action
]);
