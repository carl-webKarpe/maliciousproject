<?php
// Device status and query helpers shared by admin/devices.php and the
// super-admin dashboard.

require_once __DIR__ . DIRECTORY_SEPARATOR . "bootstrap.php";

// Columns every device listing needs, including heartbeat age in seconds
// measured by the database clock.
const MG_DEVICE_COLUMNS = "d.device_id, d.display_name, d.hostname, d.username, d.os_name, d.agent_version, d.ip_address,
    d.status, d.registered_at, d.created_at, d.last_heartbeat_at, d.heartbeat_interval, d.last_auth_failure_at,
    d.last_agent_error, d.queue_depth, d.monitored_paths, d.rotate_requested, d.pending_credential_hash, d.revoked_at,
    TIMESTAMPDIFF(SECOND, d.last_heartbeat_at, NOW()) AS heartbeat_age,
    (d.last_auth_failure_at IS NOT NULL AND (d.last_heartbeat_at IS NULL OR d.last_auth_failure_at > d.last_heartbeat_at)) AS auth_failing";

// Returns [css class, label, explanation]. Online means an authenticated
// heartbeat arrived within the offline window; nothing else counts.
function mg_device_status(array $device): array
{
    if ($device["status"] === "revoked") {
        return ["revoked", "Revoked", "Credential revoked by an administrator. The agent can no longer connect."];
    }
    if ($device["status"] === "legacy") {
        return ["legacy", "Re-enroll required", "Reported by the old shared-token agent. Install the Python agent and enroll with a token."];
    }
    if (!empty($device["auth_failing"])) {
        return ["auth-failed", "Authentication failed", "A request with a wrong credential arrived after the last good heartbeat. Rotate or re-enroll the device."];
    }
    if ($device["last_heartbeat_at"] === null) {
        return ["no-heartbeat", "Registered, no heartbeat yet", "Enrolled, but the agent has not started monitoring yet."];
    }
    $window = mg_online_window((int) $device["heartbeat_interval"]);
    if ((int) $device["heartbeat_age"] <= $window) {
        if (!empty($device["last_agent_error"])) {
            return ["online", "Online (agent reported a problem)", (string) $device["last_agent_error"]];
        }
        return ["online", "Online", "Last authenticated heartbeat " . mg_format_age((int) $device["heartbeat_age"]) . " ago."];
    }
    $explain = "No heartbeat for " . mg_format_age((int) $device["heartbeat_age"]) . ".";
    if (!empty($device["last_agent_error"])) {
        $explain .= " Last connection problem the agent reported: " . $device["last_agent_error"];
    }
    return ["offline", "Offline", $explain];
}

function mg_format_age(int $seconds): string
{
    if ($seconds < 90) {
        return max(0, $seconds) . "s";
    }
    if ($seconds < 5400) {
        return round($seconds / 60) . " min";
    }
    if ($seconds < 172800) {
        return round($seconds / 3600) . " h";
    }
    return round($seconds / 86400) . " days";
}

function mg_format_bytes(?int $bytes): string
{
    if ($bytes === null) {
        return "—";
    }
    $units = ["bytes", "KB", "MB", "GB"];
    $value = (float) $bytes;
    $unit = 0;
    while ($value >= 1024 && $unit < count($units) - 1) {
        $value /= 1024;
        $unit++;
    }
    return ($unit === 0 ? number_format($value) : number_format($value, 1)) . " " . $units[$unit];
}

function mg_device_label(array $device): string
{
    return (string) ($device["display_name"] ?: ($device["hostname"] ?: $device["device_id"]));
}

function mg_device_summary(PDO $pdo): array
{
    $devices = $pdo->query("SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d")->fetchAll();
    $summary = ["total" => 0, "online" => 0, "offline" => 0, "attention" => 0];
    foreach ($devices as $device) {
        if (in_array($device["status"], ["revoked", "legacy"], true)) {
            continue;
        }
        $summary["total"]++;
        [$class] = mg_device_status($device);
        if ($class === "online") {
            $summary["online"]++;
        } else {
            $summary["offline"]++;
        }
        if ($class === "auth-failed") {
            $summary["attention"]++;
        }
    }
    return $summary;
}
