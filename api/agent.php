<?php
// Endpoint agent API.
//
// Every request is POST. The action comes from ?action= or the JSON body.
//   enroll             exchange a one-time enrollment token for a device credential
//   heartbeat          report status; the response carries pending scan jobs
//   events             submit a batch of file events (idempotent via event_uid)
//   scan_upload        multipart upload of a file for a scan job the server issued
//   scan_failed        report that a scan job could not be carried out
//   rotate_credential  get a new device credential
//
// All actions except enroll require the X-Device-Id and X-Device-Credential
// headers. The API never asks an agent to execute anything or to read files
// outside the directories the operator approved in the agent's configuration.

require_once __DIR__ . "/../includes/scan_engine.php";

header("Content-Type: application/json");
header("Cache-Control: no-store");

const EVENT_TYPES = ["created", "modified", "moved", "deleted"];
const MAX_EVENTS_PER_BATCH = 200;

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload + ["server_time" => time()], JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $status, string $code, string $message): never
{
    respond($status, ["ok" => false, "error" => $code, "message" => $message]);
}

function clean_text(mixed $value, int $maxLength): string
{
    $text = is_scalar($value) ? trim((string) $value) : "";
    $text = preg_replace('/[\x00-\x1F\x7F]/u', "", $text) ?? "";
    return mb_substr($text, 0, $maxLength);
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    fail(405, "method_not_allowed", "Use POST.");
}

try {
    $pdo = mg_pdo();
} catch (Throwable $e) {
    error_log("Agent API database connection failed: " . $e->getMessage());
    fail(503, "database_unavailable", "The server database is unavailable.");
}

$ip = mg_client_ip();
if (!mg_rate_limit("agent:ip:" . $ip, mg_setting_int("AGENT_REQUESTS_PER_MINUTE", 120, 10, 10000), 60)) {
    fail(429, "rate_limited", "Too many requests from this address. Slow down and retry.");
}

$action = clean_text($_GET["action"] ?? "", 32);
$payload = [];
if ($action !== "scan_upload") {
    if ((int) ($_SERVER["CONTENT_LENGTH"] ?? 0) > 1024 * 1024) {
        fail(413, "payload_too_large", "JSON requests are limited to 1 MB.");
    }
    $decoded = json_decode((string) file_get_contents("php://input"), true);
    if (!is_array($decoded)) {
        fail(400, "invalid_json", "Request body must be a JSON object.");
    }
    $payload = $decoded;
    if ($action === "") {
        $action = clean_text($payload["action"] ?? "", 32);
    }
}

/*
|--------------------------------------------------------------------------
| Enrollment (the only unauthenticated action)
|--------------------------------------------------------------------------
*/

if ($action === "enroll") {
    if (!mg_rate_limit("agent:enroll:" . $ip, 10, 600)) {
        fail(429, "rate_limited", "Too many enrollment attempts from this address. Wait 10 minutes.");
    }

    $token = clean_text($payload["enrollment_token"] ?? "", 128);
    $deviceId = clean_text($payload["device_id"] ?? "", 64);
    $hostname = clean_text($payload["hostname"] ?? "", 255);
    $displayName = clean_text($payload["display_name"] ?? "", 255);

    if (!preg_match('/^[A-Za-z0-9-]{8,64}$/', $deviceId)) {
        fail(400, "invalid_device_id", "device_id must be 8-64 letters, digits or hyphens.");
    }
    if ($token === "") {
        fail(400, "missing_token", "enrollment_token is required.");
    }

    $pdo->beginTransaction();
    $tokenStmt = $pdo->prepare(
        "SELECT id, label, expires_at > NOW() AS is_current, used_at, revoked_at
         FROM enrollment_tokens WHERE token_hash = ? FOR UPDATE"
    );
    $tokenStmt->execute([mg_hash_secret($token)]);
    $tokenRow = $tokenStmt->fetch();

    if (!$tokenRow || !$tokenRow["is_current"] || $tokenRow["used_at"] !== null || $tokenRow["revoked_at"] !== null) {
        $pdo->rollBack();
        mg_audit("device", $deviceId, "device.enroll_rejected", $hostname, [
            "reason" => !$tokenRow ? "unknown_token" : ($tokenRow["revoked_at"] !== null ? "revoked" : ($tokenRow["used_at"] !== null ? "already_used" : "expired")),
        ]);
        fail(401, "invalid_token", "The enrollment token is invalid, expired, revoked or already used. Ask an administrator for a new token.");
    }

    $existing = $pdo->prepare("SELECT status FROM endpoint_devices WHERE device_id = ? FOR UPDATE");
    $existing->execute([$deviceId]);
    $existingStatus = $existing->fetchColumn();
    if ($existingStatus === "active") {
        $pdo->rollBack();
        fail(409, "already_registered", "This device ID is already registered. An administrator must revoke it before it can enroll again.");
    }

    $credential = mg_random_token(32);
    $interval = mg_setting_int("AGENT_HEARTBEAT_SECONDS", 30, 10, 3600);
    $deviceStmt = $pdo->prepare(
        "INSERT INTO endpoint_devices
            (device_id, display_name, hostname, username, os_name, agent_version, ip_address, credential_hash,
             pending_credential_hash, rotate_requested, status, enrollment_token_id, registered_at, last_seen_at,
             heartbeat_interval, revoked_at, last_auth_failure_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 'active', ?, NOW(), NOW(), ?, NULL, NULL)
         ON DUPLICATE KEY UPDATE
            display_name = VALUES(display_name), hostname = VALUES(hostname), username = VALUES(username),
            os_name = VALUES(os_name), agent_version = VALUES(agent_version), ip_address = VALUES(ip_address),
            credential_hash = VALUES(credential_hash), pending_credential_hash = NULL, rotate_requested = 0,
            status = 'active', enrollment_token_id = VALUES(enrollment_token_id), registered_at = NOW(),
            last_seen_at = NOW(), heartbeat_interval = VALUES(heartbeat_interval), revoked_at = NULL,
            last_auth_failure_at = NULL"
    );
    $deviceStmt->execute([
        $deviceId,
        $displayName !== "" ? $displayName : ($tokenRow["label"] ?: $hostname),
        $hostname,
        clean_text($payload["username"] ?? "", 255),
        clean_text($payload["os_name"] ?? "", 255),
        clean_text($payload["agent_version"] ?? "", 32),
        $ip,
        mg_hash_secret($credential),
        (int) $tokenRow["id"],
        $interval,
    ]);
    $pdo->prepare("UPDATE enrollment_tokens SET used_at = NOW(), used_by_device = ? WHERE id = ?")
        ->execute([$deviceId, (int) $tokenRow["id"]]);
    $pdo->commit();

    mg_audit("device", $deviceId, "device.enrolled", $hostname, ["token_id" => (int) $tokenRow["id"], "re_enrolled" => $existingStatus !== false]);

    respond(200, [
        "ok" => true,
        "device_id" => $deviceId,
        "device_credential" => $credential,
        "heartbeat_interval" => $interval,
        "message" => "Device registered.",
    ]);
}

/*
|--------------------------------------------------------------------------
| Device authentication
|--------------------------------------------------------------------------
*/

$deviceId = clean_text($_SERVER["HTTP_X_DEVICE_ID"] ?? "", 64);
$credential = (string) ($_SERVER["HTTP_X_DEVICE_CREDENTIAL"] ?? "");

if ($deviceId === "" || $credential === "") {
    fail(401, "missing_credentials", "X-Device-Id and X-Device-Credential headers are required. Enroll the device first.");
}

$deviceStmt = $pdo->prepare("SELECT * FROM endpoint_devices WHERE device_id = ?");
$deviceStmt->execute([$deviceId]);
$device = $deviceStmt->fetch();
$presentedHash = mg_hash_secret($credential);

// A revoked device's credential is erased, so tell its agent why it is refused.
if ($device && $device["status"] === "revoked") {
    mg_audit("device", $deviceId, "device.rejected_revoked");
    fail(403, "device_revoked", "This device has been revoked by an administrator. Re-enroll it with a new token to use it again.");
}

$matchesCurrent = $device && $device["credential_hash"] !== null && hash_equals($device["credential_hash"], $presentedHash);
$matchesPending = $device && $device["pending_credential_hash"] !== null && hash_equals($device["pending_credential_hash"], $presentedHash);

if (!$device || (!$matchesCurrent && !$matchesPending)) {
    if ($device) {
        $pdo->prepare("UPDATE endpoint_devices SET last_auth_failure_at = NOW() WHERE id = ?")->execute([(int) $device["id"]]);
    }
    if (!mg_rate_limit("agent:authfail:" . $ip, 20, 600)) {
        fail(429, "rate_limited", "Too many failed authentication attempts.");
    }
    mg_audit("device", $deviceId, "device.auth_failed", null, ["known_device" => (bool) $device]);
    fail(401, "auth_failed", "Device authentication failed. Re-enroll the agent with a new token.");
}

if ($device["status"] !== "active") {
    mg_audit("device", $deviceId, "device.rejected_" . $device["status"]);
    fail(403, "device_" . $device["status"], "This device has been revoked by an administrator.");
}

// The agent proved it received the rotated credential: retire the old one.
if ($matchesPending) {
    $pdo->prepare(
        "UPDATE endpoint_devices SET credential_hash = pending_credential_hash, pending_credential_hash = NULL,
             credential_rotated_at = NOW() WHERE id = ?"
    )->execute([(int) $device["id"]]);
    mg_audit("device", $deviceId, "device.credential_rotated");
}

/*
|--------------------------------------------------------------------------
| Heartbeat
|--------------------------------------------------------------------------
*/

if ($action === "heartbeat") {
    $paths = $payload["monitored_paths"] ?? [];
    $paths = is_array($paths) ? array_slice(array_map(static fn ($p) => clean_text($p, 400), $paths), 0, 20) : [];
    $interval = filter_var($payload["heartbeat_interval"] ?? null, FILTER_VALIDATE_INT, ["options" => ["min_range" => 10, "max_range" => 3600]]);

    $pdo->prepare(
        "UPDATE endpoint_devices SET
            hostname = ?, username = ?, os_name = ?, agent_version = ?, ip_address = ?,
            queue_depth = ?, last_agent_error = ?, monitored_paths = ?, heartbeat_interval = ?,
            last_heartbeat_at = NOW(), last_seen_at = NOW()
         WHERE id = ?"
    )->execute([
        clean_text($payload["hostname"] ?? $device["hostname"], 255),
        clean_text($payload["username"] ?? $device["username"], 255),
        clean_text($payload["os_name"] ?? $device["os_name"], 255),
        clean_text($payload["agent_version"] ?? $device["agent_version"], 32),
        $ip,
        max(0, min(4294967295, (int) ($payload["queue_depth"] ?? 0))),
        ($error = clean_text($payload["last_error"] ?? "", 500)) === "" ? null : $error,
        json_encode($paths, JSON_UNESCAPED_SLASHES),
        $interval ?: (int) $device["heartbeat_interval"],
        (int) $device["id"],
    ]);

    // Jobs dispatched more than 10 minutes ago without an answer are offered
    // again, up to three attempts in total.
    $pdo->prepare(
        "UPDATE scan_requests SET status = 'failed', completed_at = NOW(),
             error_message = 'The agent did not complete the scan after 3 attempts.'
         WHERE device_id = ? AND status = 'dispatched' AND attempts >= 3
           AND dispatched_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)"
    )->execute([$deviceId]);

    $jobsStmt = $pdo->prepare(
        "SELECT id, file_path, sha256 FROM scan_requests
         WHERE device_id = ?
           AND (status = 'pending' OR (status = 'dispatched' AND dispatched_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)))
         ORDER BY id ASC LIMIT 5"
    );
    $jobsStmt->execute([$deviceId]);
    $jobs = $jobsStmt->fetchAll();
    if ($jobs) {
        $ids = array_column($jobs, "id");
        $placeholders = implode(",", array_fill(0, count($ids), "?"));
        $pdo->prepare(
            "UPDATE scan_requests SET status = 'dispatched', dispatched_at = NOW(), attempts = attempts + 1
             WHERE id IN ($placeholders)"
        )->execute($ids);
    }

    respond(200, [
        "ok" => true,
        "heartbeat_interval" => $interval ?: (int) $device["heartbeat_interval"],
        "rotate_credential" => (bool) $device["rotate_requested"],
        "max_upload_bytes" => mg_setting_int("AGENT_MAX_UPLOAD_MB", 50, 1, 500) * 1024 * 1024,
        "scan_jobs" => array_map(static fn (array $job): array => [
            "id" => (int) $job["id"],
            "path" => $job["file_path"],
            "sha256" => $job["sha256"],
        ], $jobs),
    ]);
}

/*
|--------------------------------------------------------------------------
| File events
|--------------------------------------------------------------------------
*/

if ($action === "events") {
    $events = $payload["events"] ?? null;
    if (!is_array($events) || !array_is_list($events)) {
        fail(400, "invalid_events", "events must be a list.");
    }
    if (count($events) > MAX_EVENTS_PER_BATCH) {
        fail(413, "batch_too_large", "Send at most " . MAX_EVENTS_PER_BATCH . " events per request.");
    }

    $insert = $pdo->prepare(
        "INSERT IGNORE INTO file_events
            (device_id, event_uid, event_type, file_path, previous_path, file_name, file_size, sha256, hash_note,
             is_potential_download, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    $autoScan = mg_setting_bool("AUTO_SCAN_NEW_FILES");
    $maxUpload = mg_setting_int("AGENT_MAX_UPLOAD_MB", 50, 1, 500) * 1024 * 1024;
    $accepted = [];
    $rejected = [];
    $inserted = 0;
    $autoQueued = 0;

    foreach ($events as $event) {
        $uid = is_array($event) ? strtolower(clean_text($event["event_uid"] ?? "", 64)) : "";
        $type = is_array($event) ? clean_text($event["event_type"] ?? "", 32) : "";
        $path = is_array($event) ? clean_text($event["path"] ?? "", 1024) : "";
        $sha256 = is_array($event) ? strtolower(clean_text($event["sha256"] ?? "", 64)) : "";
        $size = is_array($event) ? filter_var($event["size"] ?? null, FILTER_VALIDATE_INT, ["options" => ["min_range" => 0]]) : false;

        if (!preg_match('/^[a-f0-9]{64}$/', $uid) || !in_array($type, EVENT_TYPES, true) || $path === "") {
            $rejected[] = ["event_uid" => $uid, "reason" => "event_uid, event_type and path are required and must be valid"];
            continue;
        }
        if ($sha256 !== "" && !preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            $sha256 = "";
        }

        $fileName = clean_text(basename(str_replace("\\", "/", $path)), 255);
        $isDownload = !empty($event["is_potential_download"]) ? 1 : 0;
        $previous = clean_text($event["previous_path"] ?? "", 1024);
        $insert->execute([
            $deviceId,
            $uid,
            $type,
            $path,
            $previous === "" ? null : $previous,
            $fileName !== "" ? $fileName : $path,
            $size === false ? null : $size,
            $sha256 === "" ? null : $sha256,
            ($note = clean_text($event["hash_note"] ?? "", 255)) === "" ? null : $note,
            $isDownload,
            mg_epoch_to_db($event["occurred_at"] ?? null),
        ]);
        $accepted[] = $uid;

        if ($insert->rowCount() === 0) {
            continue; // already stored: a retry of an event we have
        }
        $inserted++;

        if ($autoScan && $isDownload && $sha256 !== "" && $size !== false && $size <= $maxUpload) {
            $eventId = (int) $pdo->lastInsertId();
            $queue = $pdo->prepare(
                "INSERT INTO scan_requests (device_id, file_event_id, file_path, sha256, requested_by)
                 SELECT ?, ?, ?, ?, NULL FROM DUAL
                 WHERE NOT EXISTS (
                     SELECT 1 FROM scan_requests
                     WHERE device_id = ? AND sha256 = ? AND status IN ('pending', 'dispatched', 'completed')
                 )"
            );
            $queue->execute([$deviceId, $eventId, $path, $sha256, $deviceId, $sha256]);
            $autoQueued += $queue->rowCount();
        }
    }

    $pdo->prepare("UPDATE endpoint_devices SET last_seen_at = NOW() WHERE id = ?")->execute([(int) $device["id"]]);

    respond(200, [
        "ok" => true,
        "accepted" => $accepted,
        "rejected" => $rejected,
        "inserted" => $inserted,
        "duplicates" => count($accepted) - $inserted,
        "auto_scans_queued" => $autoQueued,
    ]);
}

/*
|--------------------------------------------------------------------------
| Scan jobs
|--------------------------------------------------------------------------
*/

function load_scan_request(PDO $pdo, string $deviceId, mixed $requestId): array
{
    $id = filter_var($requestId, FILTER_VALIDATE_INT, ["options" => ["min_range" => 1]]);
    if ($id === false) {
        fail(400, "invalid_request_id", "request_id is required.");
    }
    $stmt = $pdo->prepare("SELECT * FROM scan_requests WHERE id = ? AND device_id = ?");
    $stmt->execute([$id, $deviceId]);
    $request = $stmt->fetch();
    if (!$request) {
        fail(404, "unknown_request", "No such scan job for this device.");
    }
    if (!in_array($request["status"], ["pending", "dispatched"], true)) {
        fail(409, "request_closed", "This scan job is already " . $request["status"] . ".");
    }
    return $request;
}

if ($action === "scan_failed") {
    $request = load_scan_request($pdo, $deviceId, $payload["request_id"] ?? null);
    $reason = clean_text($payload["reason"] ?? "error", 32);
    $message = clean_text($payload["message"] ?? "", 400);
    $pdo->prepare("UPDATE scan_requests SET status = 'failed', completed_at = NOW(), error_message = ? WHERE id = ?")
        ->execute([substr($reason . ($message !== "" ? ": " . $message : ""), 0, 500), (int) $request["id"]]);
    respond(200, ["ok" => true, "message" => "Scan job marked as failed."]);
}

if ($action === "scan_upload") {
    $request = load_scan_request($pdo, $deviceId, $_POST["request_id"] ?? null);
    $file = $_FILES["file"] ?? null;
    $maxUpload = mg_setting_int("AGENT_MAX_UPLOAD_MB", 50, 1, 500) * 1024 * 1024;

    if (!is_array($file) || !is_int($file["error"] ?? null) || $file["error"] !== UPLOAD_ERR_OK || !is_uploaded_file($file["tmp_name"])) {
        $code = is_array($file) ? (int) ($file["error"] ?? -1) : -1;
        fail(400, "upload_failed", "The file upload failed (code {$code}). Check the server's upload_max_filesize and post_max_size.");
    }
    if ($file["size"] > $maxUpload) {
        fail(413, "file_too_large", "The file exceeds the " . ($maxUpload / 1048576) . " MB scan limit.");
    }

    $originalName = clean_text(basename(str_replace("\\", "/", $request["file_path"])), 255);
    $result = mg_scan_file($file["tmp_name"], $originalName);

    $claimedHash = strtolower(clean_text($_POST["sha256"] ?? "", 64));
    if ($claimedHash !== "" && !hash_equals($claimedHash, $result["file_hash"])) {
        fail(400, "hash_mismatch", "The uploaded content does not match the declared SHA-256 hash.");
    }
    if ($request["sha256"] !== null && $request["sha256"] !== $result["file_hash"]) {
        $result["analysis_result"] .= " Note: the file changed after the original event was recorded (the hash differs); this result describes the current content.";
    }

    try {
        $scanId = mg_store_scan($pdo, $result, [
            "user_id" => (int) ($request["requested_by"] ?? 0),
            "file_name" => $originalName,
            "original_file_name" => $originalName,
            "file_path" => "device:" . $deviceId,
            "scan_source" => "agent",
            "device_id" => $deviceId,
            "scan_request_id" => (int) $request["id"],
            "source_path" => $request["file_path"],
        ]);
    } catch (Throwable $e) {
        error_log("Storing agent scan failed: " . $e->getMessage());
        fail(500, "store_failed", "The scan ran but could not be saved.");
    }

    $pdo->prepare("UPDATE scan_requests SET status = 'completed', completed_at = NOW(), scan_id = ?, error_message = NULL WHERE id = ?")
        ->execute([$scanId, (int) $request["id"]]);

    if (in_array($result["threat_level"], ["high", "critical"], true)) {
        $pdo->prepare("INSERT INTO endpoint_alerts (device_id, alert_type, severity, message) VALUES (?, 'file_scan_threat', ?, ?)")
            ->execute([
                $deviceId,
                $result["threat_level"],
                substr("Scan #{$scanId}: {$request["file_path"]} classified " . strtoupper($result["threat_level"]) .
                    ($result["detection_ratio"] !== null ? " (VirusTotal {$result["detection_ratio"]})" : "") . ". " . $result["recommended_action"], 0, 2000),
            ]);
    }

    mg_audit("device", $deviceId, "scan.completed", "scan:" . $scanId, ["request_id" => (int) $request["id"], "threat_level" => $result["threat_level"]]);

    respond(200, [
        "ok" => true,
        "scan_id" => $scanId,
        "threat_level" => $result["threat_level"],
        "detection_ratio" => $result["detection_ratio"],
        "message" => "Scan completed.",
    ]);
}

/*
|--------------------------------------------------------------------------
| Credential rotation
|--------------------------------------------------------------------------
|
| The new credential is stored as "pending" and the old one keeps working
| until the agent authenticates with the new one, so a lost response cannot
| lock the agent out.
|
*/

if ($action === "rotate_credential") {
    $newCredential = mg_random_token(32);
    $pdo->prepare("UPDATE endpoint_devices SET pending_credential_hash = ?, rotate_requested = 0 WHERE id = ?")
        ->execute([mg_hash_secret($newCredential), (int) $device["id"]]);
    respond(200, ["ok" => true, "device_credential" => $newCredential, "message" => "Store the new credential and use it from the next request."]);
}

fail(400, "unknown_action", "Unsupported action.");
