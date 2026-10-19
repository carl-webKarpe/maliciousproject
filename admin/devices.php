<?php
// Device management: enrollment tokens, registered computers, file events,
// agent scan requests and scan results. Admins and verified super admins only.

require_once __DIR__ . "/../includes/devices.php";

$admin = mg_require_admin_session();
if (!$admin) {
    header("Location: login.html");
    exit;
}

try {
    $pdo = mg_pdo();
} catch (Throwable $e) {
    error_log("Devices page database error: " . $e->getMessage());
    http_response_code(503);
    exit("The database is unavailable. Check that the MySQL Server service is running.");
}

$csrf = $_SESSION["devices_csrf"] ??= bin2hex(random_bytes(32));
$actorId = (string) $admin["id"];

function redirect_back(string $notice, bool $isError = false, string $anchor = ""): never
{
    $_SESSION["devices_notice"] = [$notice, $isError];
    $query = isset($_POST["return_query"]) && is_string($_POST["return_query"]) ? $_POST["return_query"] : "";
    header("Location: devices.php" . ($query !== "" ? "?" . $query : "") . $anchor);
    exit;
}

function post_string(string $key, int $maxLength = 255): string
{
    $value = $_POST[$key] ?? "";
    return is_string($value) ? mb_substr(trim($value), 0, $maxLength) : "";
}

/*
|--------------------------------------------------------------------------
| Actions
|--------------------------------------------------------------------------
*/

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!hash_equals($csrf, post_string("csrf_token", 128))) {
        redirect_back("The form expired. Reload the page and try again.", true);
    }

    $action = post_string("action", 32);

    if ($action === "create_token") {
        $label = post_string("label", 100);
        $hours = filter_var($_POST["ttl_hours"] ?? "", FILTER_VALIDATE_INT, ["options" => ["min_range" => 1, "max_range" => 168]]);
        if ($label === "") {
            redirect_back("Give the token a label, for example the computer's name or room.", true, "#tokens");
        }
        if ($hours === false) {
            redirect_back("Choose an expiry between 1 and 168 hours.", true, "#tokens");
        }
        $token = "mg_" . mg_random_token(24);
        $pdo->prepare(
            "INSERT INTO enrollment_tokens (token_hash, token_hint, label, created_by, expires_at)
             VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR))"
        )->execute([mg_hash_secret($token), substr($token, 0, 9), $label, $admin["id"], $hours]);
        mg_audit("user", $actorId, "token.created", "token:" . $pdo->lastInsertId(), ["label" => $label, "ttl_hours" => $hours]);
        // Shown exactly once; only the hash is stored.
        $_SESSION["devices_new_token"] = ["token" => $token, "label" => $label, "hours" => $hours];
        redirect_back("Enrollment token created.", false, "#tokens");
    }

    if ($action === "revoke_token") {
        $id = filter_var($_POST["token_id"] ?? "", FILTER_VALIDATE_INT);
        $stmt = $pdo->prepare("UPDATE enrollment_tokens SET revoked_at = NOW() WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL");
        $stmt->execute([$id ?: 0]);
        if ($stmt->rowCount() === 0) {
            redirect_back("That token is already used, revoked or does not exist.", true, "#tokens");
        }
        mg_audit("user", $actorId, "token.revoked", "token:" . $id);
        redirect_back("Token revoked. It can no longer be used to register a device.", false, "#tokens");
    }

    $deviceId = post_string("device_id", 128);

    if ($action === "rename_device") {
        $name = post_string("display_name", 100);
        if ($name === "") {
            redirect_back("Enter a device name.", true, "#devices");
        }
        $pdo->prepare("UPDATE endpoint_devices SET display_name = ? WHERE device_id = ?")->execute([$name, $deviceId]);
        mg_audit("user", $actorId, "device.renamed", "device:" . $deviceId, ["name" => $name]);
        redirect_back("Device renamed.", false, "#devices");
    }

    if ($action === "revoke_device") {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare(
            "UPDATE endpoint_devices SET status = 'revoked', revoked_at = NOW(), credential_hash = NULL,
                 pending_credential_hash = NULL, rotate_requested = 0
             WHERE device_id = ? AND status <> 'revoked'"
        );
        $stmt->execute([$deviceId]);
        $pdo->prepare(
            "UPDATE scan_requests SET status = 'cancelled', completed_at = NOW(), error_message = 'Device revoked'
             WHERE device_id = ? AND status IN ('pending', 'dispatched')"
        )->execute([$deviceId]);
        $pdo->commit();
        if ($stmt->rowCount() === 0) {
            redirect_back("That device is already revoked.", true, "#devices");
        }
        mg_audit("user", $actorId, "device.revoked", "device:" . $deviceId);
        redirect_back("Device revoked. Its credential no longer works; to use it again, generate a new token and re-enroll it.", false, "#devices");
    }

    if ($action === "rotate_credential") {
        $stmt = $pdo->prepare("UPDATE endpoint_devices SET rotate_requested = 1 WHERE device_id = ? AND status = 'active'");
        $stmt->execute([$deviceId]);
        if ($stmt->rowCount() === 0) {
            redirect_back("Credential rotation is only possible for active devices (or is already requested).", true, "#devices");
        }
        mg_audit("user", $actorId, "device.rotation_requested", "device:" . $deviceId);
        redirect_back("Rotation requested. The agent receives a new credential on its next heartbeat.", false, "#devices");
    }

    if ($action === "request_scan") {
        $eventId = filter_var($_POST["event_id"] ?? "", FILTER_VALIDATE_INT) ?: 0;
        $eventStmt = $pdo->prepare(
            "SELECT e.id, e.device_id, e.file_path, e.sha256, e.event_type, d.status
             FROM file_events e JOIN endpoint_devices d ON d.device_id = e.device_id WHERE e.id = ?"
        );
        $eventStmt->execute([$eventId]);
        $event = $eventStmt->fetch();
        if (!$event) {
            redirect_back("That file event no longer exists.", true, "#events");
        }
        if ($event["event_type"] === "deleted") {
            redirect_back("The file was deleted, so there is nothing to scan.", true, "#events");
        }
        if ($event["status"] !== "active") {
            redirect_back("The device is not active, so it cannot perform scans.", true, "#events");
        }
        $open = $pdo->prepare("SELECT COUNT(*) FROM scan_requests WHERE file_event_id = ? AND status IN ('pending', 'dispatched')");
        $open->execute([$eventId]);
        if ((int) $open->fetchColumn() > 0) {
            redirect_back("A scan for this file is already waiting for the agent.", true, "#events");
        }
        $pdo->prepare(
            "INSERT INTO scan_requests (device_id, file_event_id, file_path, sha256, requested_by) VALUES (?, ?, ?, ?, ?)"
        )->execute([$event["device_id"], $eventId, $event["file_path"], $event["sha256"], $admin["id"]]);
        mg_audit("user", $actorId, "scan.requested", "event:" . $eventId, ["device" => $event["device_id"], "path" => $event["file_path"]]);
        redirect_back("Scan requested. The agent uploads the file to this server for analysis on its next heartbeat; only the file's hash is sent to VirusTotal.", false, "#events");
    }

    if ($action === "cancel_scan") {
        $requestId = filter_var($_POST["request_id"] ?? "", FILTER_VALIDATE_INT) ?: 0;
        $stmt = $pdo->prepare(
            "UPDATE scan_requests SET status = 'cancelled', completed_at = NOW(), error_message = 'Cancelled by administrator'
             WHERE id = ? AND status IN ('pending', 'dispatched')"
        );
        $stmt->execute([$requestId]);
        if ($stmt->rowCount() === 0) {
            redirect_back("That scan request is no longer waiting.", true, "#scans");
        }
        mg_audit("user", $actorId, "scan.cancelled", "request:" . $requestId);
        redirect_back("Scan request cancelled.", false, "#scans");
    }

    redirect_back("Unknown action.", true);
}

/*
|--------------------------------------------------------------------------
| Data
|--------------------------------------------------------------------------
*/

$stats = mg_device_summary($pdo);
$counts = $pdo->query(
    "SELECT
        (SELECT COUNT(*) FROM enrollment_tokens WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()) AS awaiting,
        (SELECT COUNT(*) FROM file_events WHERE occurred_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS events_24h,
        (SELECT COUNT(*) FROM file_events WHERE is_potential_download = 1 AND occurred_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS new_files_24h,
        (SELECT COUNT(*) FROM scan_requests WHERE status IN ('pending', 'dispatched')) AS pending_scans,
        (SELECT COUNT(*) FROM scan_requests WHERE status = 'completed') AS completed_scans,
        (SELECT COUNT(*) FROM scans WHERE device_id IS NOT NULL AND threat_level IN ('high', 'critical')) AS threats"
)->fetch();

if (($_GET["format"] ?? "") === "json") {
    header("Content-Type: application/json");
    header("Cache-Control: no-store");
    $rows = $pdo->query("SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d")->fetchAll();
    $devicesJson = [];
    foreach ($rows as $row) {
        [$class, $label, $explain] = mg_device_status($row);
        $devicesJson[] = [
            "device_id" => $row["device_id"],
            "status_class" => $class,
            "status_label" => $label,
            "status_detail" => $explain,
            "last_heartbeat_at" => $row["last_heartbeat_at"],
            "ip_address" => $row["ip_address"],
            "queue_depth" => (int) $row["queue_depth"],
        ];
    }
    echo json_encode([
        "ok" => true,
        "stats" => [
            "total" => $stats["total"], "online" => $stats["online"], "offline" => $stats["offline"],
            "awaiting" => (int) $counts["awaiting"], "events_24h" => (int) $counts["events_24h"],
            "new_files_24h" => (int) $counts["new_files_24h"], "pending_scans" => (int) $counts["pending_scans"],
            "completed_scans" => (int) $counts["completed_scans"], "threats" => (int) $counts["threats"],
        ],
        "devices" => $devicesJson,
    ]);
    exit;
}

$devices = $pdo->query(
    "SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d
     ORDER BY FIELD(d.status, 'active', 'legacy', 'revoked'), d.last_heartbeat_at IS NULL, d.last_heartbeat_at DESC, d.id DESC"
)->fetchAll();

$tokens = $pdo->query(
    "SELECT t.id, t.token_hint, t.label, t.created_at, t.expires_at, t.used_at, t.used_by_device, t.revoked_at,
            t.expires_at <= NOW() AS expired, u.name AS created_by_name
     FROM enrollment_tokens t LEFT JOIN users u ON u.id = t.created_by
     ORDER BY t.id DESC LIMIT 25"
)->fetchAll();

// File events with filters
$filterDevice = is_string($_GET["device"] ?? null) ? $_GET["device"] : "";
$filterType = is_string($_GET["type"] ?? null) ? $_GET["type"] : "";
$filterQuery = is_string($_GET["q"] ?? null) ? mb_substr(trim($_GET["q"]), 0, 200) : "";
$filterDownloads = ($_GET["downloads"] ?? "") === "1";
$page = max(1, (int) ($_GET["page"] ?? 1));
$perPage = 50;

$where = [];
$params = [];
if ($filterDevice !== "") {
    $where[] = "e.device_id = ?";
    $params[] = $filterDevice;
}
if (in_array($filterType, ["created", "modified", "moved", "deleted"], true)) {
    $where[] = "e.event_type = ?";
    $params[] = $filterType;
}
if ($filterQuery !== "") {
    $like = "%" . addcslashes($filterQuery, "\\%_") . "%";
    $where[] = "(e.file_name LIKE ? OR e.file_path LIKE ? OR e.sha256 LIKE ?)";
    array_push($params, $like, $like, $like);
}
if ($filterDownloads) {
    $where[] = "e.is_potential_download = 1";
}

$eventsStmt = $pdo->prepare(
    "SELECT e.*, d.display_name, d.hostname, d.status AS device_status,
            sr.id AS request_id, sr.status AS request_status, sr.error_message AS request_error,
            s.id AS scan_id, s.threat_level AS scan_threat,
            hs.id AS hash_scan_id, hs.threat_level AS hash_scan_threat
     FROM file_events e
     JOIN endpoint_devices d ON d.device_id = e.device_id
     LEFT JOIN scan_requests sr ON sr.id = (SELECT MAX(id) FROM scan_requests WHERE file_event_id = e.id)
     LEFT JOIN scans s ON s.id = sr.scan_id
     LEFT JOIN scans hs ON hs.id = (SELECT MAX(id) FROM scans WHERE e.sha256 IS NOT NULL AND file_hash = e.sha256)
     " . ($where ? "WHERE " . implode(" AND ", $where) : "") . "
     ORDER BY e.occurred_at DESC, e.id DESC
     LIMIT " . ($perPage + 1) . " OFFSET " . (($page - 1) * $perPage)
);
$eventsStmt->execute($params);
$events = $eventsStmt->fetchAll();
$hasNextPage = count($events) > $perPage;
$events = array_slice($events, 0, $perPage);

// Scan requests and results
$filterRisk = is_string($_GET["risk"] ?? null) ? $_GET["risk"] : "";
$scanWhere = "";
$scanParams = [];
if (in_array($filterRisk, ["safe", "low", "medium", "high", "critical", "unknown"], true)) {
    $scanWhere = "WHERE s.threat_level = ?";
    $scanParams[] = $filterRisk;
} elseif ($filterRisk === "not_scanned") {
    $scanWhere = "WHERE sr.scan_id IS NULL";
}
$scansStmt = $pdo->prepare(
    "SELECT sr.id AS request_id, sr.status, sr.file_path, sr.sha256, sr.error_message, sr.created_at, sr.completed_at,
            sr.attempts, d.display_name, d.hostname, d.device_id, u.name AS requested_by_name,
            s.id AS scan_id, s.threat_level, s.vt_status, s.vt_malicious, s.vt_engines, s.scanned_at
     FROM scan_requests sr
     JOIN endpoint_devices d ON d.device_id = sr.device_id
     LEFT JOIN users u ON u.id = sr.requested_by
     LEFT JOIN scans s ON s.id = sr.scan_id
     $scanWhere
     ORDER BY sr.id DESC LIMIT 50"
);
$scansStmt->execute($scanParams);
$scanRows = $scansStmt->fetchAll();

// Selected scan detail
$scanDetail = null;
$scanFindings = [];
$detailId = filter_var($_GET["scan"] ?? "", FILTER_VALIDATE_INT);
if ($detailId) {
    $detailStmt = $pdo->prepare(
        "SELECT s.*, d.display_name, d.hostname, sr.status AS request_status, sr.created_at AS requested_at
         FROM scans s
         LEFT JOIN endpoint_devices d ON d.device_id = s.device_id
         LEFT JOIN scan_requests sr ON sr.id = s.scan_request_id
         WHERE s.id = ?"
    );
    $detailStmt->execute([$detailId]);
    $scanDetail = $detailStmt->fetch() ?: null;
    if ($scanDetail) {
        $findingStmt = $pdo->prepare("SELECT detection_name, severity, description, evidence FROM detection_results WHERE scan_id = ? ORDER BY id");
        $findingStmt->execute([$detailId]);
        $scanFindings = $findingStmt->fetchAll();
    }
}

$notice = $_SESSION["devices_notice"] ?? null;
$newToken = $_SESSION["devices_new_token"] ?? null;
unset($_SESSION["devices_notice"], $_SESSION["devices_new_token"]);

$returnQuery = http_build_query(array_filter([
    "device" => $filterDevice, "type" => $filterType, "q" => $filterQuery,
    "downloads" => $filterDownloads ? "1" : "", "risk" => $filterRisk, "page" => $page > 1 ? $page : "",
], static fn ($v) => $v !== "" && $v !== null));

$serverHost = $_SERVER["HTTP_HOST"] ?? "SERVER-IP:8000";
$scheme = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") ? "https" : "http";
$defaultTtl = mg_setting_int("ENROLLMENT_TOKEN_TTL_HOURS", 24, 1, 168);

function page_link(array $overrides): string
{
    global $filterDevice, $filterType, $filterQuery, $filterDownloads, $filterRisk;
    $query = array_merge([
        "device" => $filterDevice, "type" => $filterType, "q" => $filterQuery,
        "downloads" => $filterDownloads ? "1" : "", "risk" => $filterRisk,
    ], $overrides);
    return "devices.php?" . http_build_query(array_filter($query, static fn ($v) => $v !== "" && $v !== null));
}

function hidden_fields(string $csrf, string $returnQuery): string
{
    return '<input type="hidden" name="csrf_token" value="' . mg_h($csrf) . '">'
        . '<input type="hidden" name="return_query" value="' . mg_h($returnQuery) . '">';
}

function risk_badge(?string $level): string
{
    if ($level === null || $level === "") {
        return '<span class="badge not-scanned">Not scanned</span>';
    }
    return '<span class="badge ' . mg_h($level) . '">' . mg_h(ucfirst($level)) . '</span>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Devices | MalwareGuard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/admin-devices.css">
</head>
<body>
    <header>
        <h1>MalwareGuard devices</h1>
        <nav>
            <a href="dashboard.php">Scan activity</a>
            <?php if ($admin["role"] === "super_admin"): ?>
                <a href="../super_admin/dashboard.php">User database</a>
            <?php endif; ?>
            <a href="../logout.php">Sign out</a>
        </nav>
    </header>
    <div class="workspace">
        <aside class="sidebar" aria-label="Device navigation">
            <div class="sidebar-label">DEVICES</div>
            <a href="#overview" aria-current="page"><i class="fa-solid fa-chart-line" aria-hidden="true"></i>Overview</a>
            <a href="#devices"><i class="fa-solid fa-desktop" aria-hidden="true"></i>Computers</a>
            <a href="#tokens"><i class="fa-solid fa-key" aria-hidden="true"></i>Enrollment tokens</a>
            <a href="#events"><i class="fa-solid fa-file-circle-plus" aria-hidden="true"></i>File events</a>
            <a href="#scans"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Agent scans</a>
            <a href="dashboard.php"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i>Upload scans</a>
            <a class="sidebar-logout" href="../logout.php"><i class="fa-solid fa-right-from-bracket" aria-hidden="true"></i>Sign out</a>
        </aside>

        <main id="overview">
            <p class="intro">
                Computers appear here only after an administrator issues an enrollment token and the MalwareGuard agent registers with it.
                A device is <strong>online</strong> only while authenticated heartbeats keep arriving. Agents watch only the folders configured on each device.
                <span class="live-status" id="liveStatus" role="status" aria-live="polite"></span>
            </p>

            <?php if ($notice): ?>
                <p class="notice<?= $notice[1] ? " error" : "" ?>" role="status"><?= mg_h($notice[0]) ?></p>
            <?php endif; ?>

            <section class="stats" aria-label="Device statistics">
                <div class="stat"><span>Registered devices</span><strong data-stat="total"><?= (int) $stats["total"] ?></strong></div>
                <div class="stat ok"><span>Online</span><strong data-stat="online"><?= (int) $stats["online"] ?></strong></div>
                <div class="stat"><span>Offline</span><strong data-stat="offline"><?= (int) $stats["offline"] ?></strong></div>
                <div class="stat warn"><span>Awaiting registration</span><strong data-stat="awaiting"><?= (int) $counts["awaiting"] ?></strong></div>
                <div class="stat"><span>File events (24 h)</span><strong data-stat="events_24h"><?= (int) $counts["events_24h"] ?></strong></div>
                <div class="stat"><span>New files (24 h)</span><strong data-stat="new_files_24h"><?= (int) $counts["new_files_24h"] ?></strong></div>
                <div class="stat warn"><span>Pending scans</span><strong data-stat="pending_scans"><?= (int) $counts["pending_scans"] ?></strong></div>
                <div class="stat"><span>Completed scans</span><strong data-stat="completed_scans"><?= (int) $counts["completed_scans"] ?></strong></div>
                <div class="stat bad"><span>Threats on devices</span><strong data-stat="threats"><?= (int) $counts["threats"] ?></strong></div>
            </section>

            <?php if ($scanDetail): ?>
                <?php
                $vtFound = $scanDetail["vt_status"] === "found";
                $deviceLabel = $scanDetail["device_id"] ? (($scanDetail["display_name"] ?: $scanDetail["hostname"]) ?: $scanDetail["device_id"]) : null;
                ?>
                <section class="panel" id="scan-detail" aria-live="polite">
                    <div class="panel-head">
                        <h2>Scan #<?= (int) $scanDetail["id"] ?> result</h2>
                        <?= risk_badge($scanDetail["threat_level"]) ?>
                    </div>
                    <div class="detail-grid">
                        <div><span>File name</span><strong><?= mg_h($scanDetail["original_file_name"]) ?></strong></div>
                        <div><span>File path</span><strong><?= mg_h($scanDetail["source_path"] ?: ($scanDetail["scan_source"] === "upload" ? "Uploaded through the browser" : "—")) ?></strong></div>
                        <div><span>File size</span><strong><?= mg_h(mg_format_bytes((int) $scanDetail["file_size"])) ?></strong></div>
                        <div><span>SHA-256</span><strong><code><?= mg_h($scanDetail["file_hash"]) ?></code></strong></div>
                        <div><span>Computer</span><strong><?= $deviceLabel !== null ? mg_h($deviceLabel) . '<br><small>' . mg_h($scanDetail["device_id"]) . '</small>' : "Not from an agent" ?></strong></div>
                        <div><span>Scan status</span><strong><?= mg_h($scanDetail["request_status"] ?? "completed") ?></strong></div>
                        <div><span>Risk classification</span><strong><?= mg_h(ucfirst($scanDetail["threat_level"])) ?> (<?= mg_h($scanDetail["detection_status"]) ?>)</strong></div>
                        <div><span>Detection ratio</span><strong><?= $vtFound ? mg_h($scanDetail["vt_malicious"] . "/" . $scanDetail["vt_engines"]) . " VirusTotal engines" : "Not available (" . mg_h(str_replace("_", " ", (string) ($scanDetail["vt_status"] ?? "not checked"))) . ")" ?></strong></div>
                        <div><span>Analysed at</span><strong><?= mg_h($scanDetail["scanned_at"]) ?></strong></div>
                        <div><span>Detection source</span><strong><?= mg_h($scanDetail["detection_source"] ?: "MalwareGuard static rules") ?></strong></div>
                        <div><span>Rule-based score</span><strong><?= (int) $scanDetail["security_score"] ?>/100</strong><br><small>100 minus the points of matched indicators. Not a probability.</small></div>
                        <?php if (!empty($scanDetail["error_message"])): ?>
                            <div><span>Error</span><strong class="muted"><?= mg_h($scanDetail["error_message"]) ?></strong></div>
                        <?php endif; ?>
                    </div>
                    <div class="finding"><h3>Recommended next action</h3><p><?= mg_h($scanDetail["recommended_action"] ?: "Review the findings below.") ?></p></div>
                    <div class="finding"><h3>Analysis summary</h3><p><?= mg_h($scanDetail["analysis_result"]) ?></p></div>
                    <?php foreach ($scanFindings as $finding): ?>
                        <div class="finding">
                            <h3><?= mg_h($finding["detection_name"]) ?> · <?= mg_h(strtoupper($finding["severity"])) ?></h3>
                            <p><?= mg_h($finding["description"]) ?></p>
                            <?php if (!empty($finding["evidence"])): ?><p>Evidence: <code><?= mg_h($finding["evidence"]) ?></code></p><?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                    <?php if (!$scanFindings): ?>
                        <div class="finding"><p>No configured indicator matched. This means only that the checks above found nothing; it is not a guarantee that the file is harmless.</p></div>
                    <?php endif; ?>
                </section>
            <?php elseif ($detailId): ?>
                <p class="notice error">Scan #<?= (int) $detailId ?> was not found.</p>
            <?php endif; ?>

            <section class="panel" id="devices">
                <div class="panel-head">
                    <h2>Computers</h2>
                    <span class="badge"><?= count($devices) ?> registered</span>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Device</th><th>Status</th><th>IP address</th><th>Registered</th><th>Last heartbeat</th><th>Agent</th><th>Actions</th></tr></thead>
                        <tbody>
                        <?php if (!$devices): ?>
                            <tr><td class="empty" colspan="7">No computers are registered yet. Generate an enrollment token below and run INSTALL_AGENT.bat on the computer.</td></tr>
                        <?php endif; ?>
                        <?php foreach ($devices as $device): ?>
                            <?php [$statusClass, $statusLabel, $statusDetail] = mg_device_status($device); ?>
                            <tr data-device-id="<?= mg_h($device["device_id"]) ?>">
                                <td>
                                    <strong><?= mg_h(mg_device_label($device)) ?></strong><br>
                                    <small>ID <code><?= mg_h($device["device_id"]) ?></code></small><br>
                                    <small><?= mg_h($device["hostname"] ?: "—") ?><?= $device["os_name"] ? " · " . mg_h($device["os_name"]) : "" ?></small>
                                    <?php $paths = json_decode((string) $device["monitored_paths"], true); ?>
                                    <?php if (is_array($paths) && $paths): ?><br><small>Watching: <?= mg_h(implode(", ", $paths)) ?></small><?php endif; ?>
                                </td>
                                <td>
                                    <span class="badge <?= mg_h($statusClass) ?>" data-field="status"><?= mg_h($statusLabel) ?></span><br>
                                    <small data-field="status-detail"><?= mg_h($statusDetail) ?></small>
                                    <?php if ((int) $device["queue_depth"] > 0): ?><br><small data-field="queue"><?= (int) $device["queue_depth"] ?> event(s) queued on the device</small><?php endif; ?>
                                    <?php if ($device["rotate_requested"] || $device["pending_credential_hash"]): ?><br><small>Credential rotation in progress</small><?php endif; ?>
                                </td>
                                <td data-field="ip"><?= mg_h($device["ip_address"] ?: "—") ?></td>
                                <td><?= mg_h($device["registered_at"] ?: $device["created_at"]) ?></td>
                                <td data-field="heartbeat"><?= mg_h($device["last_heartbeat_at"] ?: "Never") ?></td>
                                <td><?= mg_h($device["agent_version"] ?: "—") ?></td>
                                <td>
                                    <?php if ($device["status"] === "active"): ?>
                                    <div class="actions">
                                        <form class="inline" method="post" action="devices.php">
                                            <?= hidden_fields($csrf, $returnQuery) ?>
                                            <input type="hidden" name="action" value="rename_device">
                                            <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                            <input type="hidden" name="display_name" value="">
                                            <button type="submit" data-rename="<?= mg_h(mg_device_label($device)) ?>"><i class="fa-solid fa-pen" aria-hidden="true"></i>Rename</button>
                                        </form>
                                        <form class="inline" method="post" action="devices.php">
                                            <?= hidden_fields($csrf, $returnQuery) ?>
                                            <input type="hidden" name="action" value="rotate_credential">
                                            <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                            <button type="submit"><i class="fa-solid fa-rotate" aria-hidden="true"></i>Rotate key</button>
                                        </form>
                                        <form class="inline" method="post" action="devices.php">
                                            <?= hidden_fields($csrf, $returnQuery) ?>
                                            <input type="hidden" name="action" value="revoke_device">
                                            <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                            <button type="submit" class="danger" data-confirm="Revoke <?= mg_h(mg_device_label($device)) ?>? Its agent will be rejected until it is re-enrolled with a new token."><i class="fa-solid fa-ban" aria-hidden="true"></i>Revoke</button>
                                        </form>
                                    </div>
                                    <?php else: ?>
                                        <small>Re-enroll with a new token to reactivate.</small>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="panel" id="tokens">
                <div class="panel-head"><h2>Enrollment tokens</h2></div>
                <p class="hint">
                    A token lets one computer register. It is shown once, works once, and expires automatically.
                    On the computer, run <code>agent\INSTALL_AGENT.bat</code> and enter the server address
                    <code><?= mg_h($scheme . "://" . $serverHost) ?></code> and the token.
                </p>
                <?php if ($newToken): ?>
                    <div class="token-box" role="alert">
                        <strong>New token for "<?= mg_h($newToken["label"]) ?>"</strong> (expires in <?= (int) $newToken["hours"] ?> h). Copy it now; it will not be shown again.
                        <code id="newToken"><?= mg_h($newToken["token"]) ?></code>
                        <button type="button" id="copyToken"><i class="fa-solid fa-copy" aria-hidden="true"></i>Copy token</button>
                        <p class="hint" style="margin:10px 0 0;">Command-line alternative on the computer:<br>
                            <code>python agent.py enroll --server <?= mg_h($scheme . "://" . $serverHost) ?> --token <?= mg_h($newToken["token"]) ?></code></p>
                    </div>
                <?php endif; ?>
                <form method="post" action="devices.php" class="form-row" style="margin-bottom:16px;">
                    <?= hidden_fields($csrf, $returnQuery) ?>
                    <input type="hidden" name="action" value="create_token">
                    <div><label for="token-label">Label (computer or room)</label><input id="token-label" name="label" maxlength="100" placeholder="Lab PC 04" required></div>
                    <div><label for="token-ttl">Expires after (hours)</label><input id="token-ttl" name="ttl_hours" type="number" min="1" max="168" value="<?= $defaultTtl ?>" required></div>
                    <div><button type="submit" class="primary"><i class="fa-solid fa-key" aria-hidden="true"></i>Generate token</button></div>
                </form>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Label</th><th>Token</th><th>State</th><th>Created</th><th>Expires</th><th>Used by</th><th></th></tr></thead>
                        <tbody>
                        <?php if (!$tokens): ?>
                            <tr><td class="empty" colspan="7">No tokens yet.</td></tr>
                        <?php endif; ?>
                        <?php foreach ($tokens as $token): ?>
                            <?php
                            if ($token["used_at"] !== null) { [$tc, $tl] = ["completed", "Used"]; }
                            elseif ($token["revoked_at"] !== null) { [$tc, $tl] = ["revoked", "Revoked"]; }
                            elseif ($token["expired"]) { [$tc, $tl] = ["offline", "Expired"]; }
                            else { [$tc, $tl] = ["awaiting", "Awaiting registration"]; }
                            ?>
                            <tr>
                                <td><?= mg_h($token["label"]) ?><br><small>by <?= mg_h($token["created_by_name"] ?? "unknown") ?></small></td>
                                <td><code><?= mg_h($token["token_hint"]) ?>…</code></td>
                                <td><span class="badge <?= $tc ?>"><?= $tl ?></span></td>
                                <td><?= mg_h($token["created_at"]) ?></td>
                                <td><?= mg_h($token["expires_at"]) ?></td>
                                <td><?= $token["used_by_device"] ? "<code>" . mg_h($token["used_by_device"]) . "</code><br><small>" . mg_h($token["used_at"]) . "</small>" : "—" ?></td>
                                <td>
                                    <?php if ($tc === "awaiting"): ?>
                                        <form class="inline" method="post" action="devices.php">
                                            <?= hidden_fields($csrf, $returnQuery) ?>
                                            <input type="hidden" name="action" value="revoke_token">
                                            <input type="hidden" name="token_id" value="<?= (int) $token["id"] ?>">
                                            <button type="submit" class="danger">Revoke</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="panel" id="events">
                <div class="panel-head"><h2>File events</h2></div>
                <p class="hint">
                    "Potential download" means a new file appeared in a monitored folder; it is not proof that a browser downloaded it.
                    <strong>Scan</strong> asks the agent to upload that file to this server for analysis; only the SHA-256 hash is sent to VirusTotal.
                </p>
                <form method="get" action="devices.php#events" class="form-row" style="margin-bottom:14px;">
                    <div><label for="f-device">Device</label>
                        <select id="f-device" name="device">
                            <option value="">All devices</option>
                            <?php foreach ($devices as $device): ?>
                                <option value="<?= mg_h($device["device_id"]) ?>"<?= $filterDevice === $device["device_id"] ? " selected" : "" ?>><?= mg_h(mg_device_label($device)) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div><label for="f-type">Event</label>
                        <select id="f-type" name="type">
                            <option value="">All events</option>
                            <?php foreach (["created", "modified", "moved", "deleted"] as $type): ?>
                                <option value="<?= $type ?>"<?= $filterType === $type ? " selected" : "" ?>><?= ucfirst($type) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div><label for="f-q">Search name, path or hash</label><input id="f-q" name="q" value="<?= mg_h($filterQuery) ?>" placeholder="invoice.pdf"></div>
                    <div><label class="check"><input type="checkbox" name="downloads" value="1"<?= $filterDownloads ? " checked" : "" ?>> Potential downloads only</label></div>
                    <div><button type="submit"><i class="fa-solid fa-filter" aria-hidden="true"></i>Filter</button> <a class="button" href="devices.php#events">Reset</a></div>
                </form>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Time</th><th>Computer</th><th>Event</th><th>File</th><th>Size</th><th>SHA-256</th><th>Scan</th></tr></thead>
                        <tbody>
                        <?php if (!$events): ?>
                            <tr><td class="empty" colspan="7"><?= ($where ? "No events match these filters." : "No file events have been reported yet. Events appear once an enrolled agent is running.") ?></td></tr>
                        <?php endif; ?>
                        <?php foreach ($events as $event): ?>
                            <tr>
                                <td><?= mg_h($event["occurred_at"]) ?></td>
                                <td><?= mg_h(($event["display_name"] ?: $event["hostname"]) ?: $event["device_id"]) ?></td>
                                <td><?= mg_h(ucfirst($event["event_type"])) ?><?= $event["is_potential_download"] ? '<br><small>Potential download</small>' : "" ?></td>
                                <td>
                                    <strong><?= mg_h($event["file_name"]) ?></strong><br>
                                    <small><?= mg_h($event["file_path"]) ?></small>
                                    <?php if ($event["previous_path"]): ?><br><small>from <?= mg_h($event["previous_path"]) ?></small><?php endif; ?>
                                </td>
                                <td><?= mg_h(mg_format_bytes($event["file_size"] === null ? null : (int) $event["file_size"])) ?></td>
                                <td><?= $event["sha256"] ? '<code title="' . mg_h($event["sha256"]) . '">' . mg_h(substr($event["sha256"], 0, 16)) . '…</code>' : '<small>' . mg_h($event["hash_note"] ?: "—") . '</small>' ?></td>
                                <td>
                                    <?php if ($event["scan_id"]): ?>
                                        <a href="<?= mg_h(page_link(["scan" => $event["scan_id"]])) ?>#scan-detail"><?= risk_badge($event["scan_threat"]) ?></a>
                                    <?php elseif ($event["request_status"] === "pending" || $event["request_status"] === "dispatched"): ?>
                                        <span class="badge pending">Scan <?= mg_h($event["request_status"]) ?></span>
                                    <?php else: ?>
                                        <?php if ($event["request_status"] === "failed"): ?>
                                            <span class="badge failed" title="<?= mg_h($event["request_error"]) ?>">Scan failed</span><br><small><?= mg_h($event["request_error"]) ?></small><br>
                                        <?php elseif ($event["hash_scan_id"]): ?>
                                            <small>Same hash scanned before:</small>
                                            <a href="<?= mg_h(page_link(["scan" => $event["hash_scan_id"]])) ?>#scan-detail"><?= risk_badge($event["hash_scan_threat"]) ?></a><br>
                                        <?php else: ?>
                                            <?= risk_badge(null) ?><br>
                                        <?php endif; ?>
                                        <?php if ($event["event_type"] !== "deleted" && $event["device_status"] === "active"): ?>
                                            <form class="inline" method="post" action="devices.php">
                                                <?= hidden_fields($csrf, $returnQuery) ?>
                                                <input type="hidden" name="action" value="request_scan">
                                                <input type="hidden" name="event_id" value="<?= (int) $event["id"] ?>">
                                                <button type="submit" style="margin-top:6px;"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Scan</button>
                                            </form>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <div class="pager">
                    <?php if ($page > 1): ?><a class="button" href="<?= mg_h(page_link(["page" => $page - 1])) ?>#events">Newer</a><?php endif; ?>
                    <span>Page <?= $page ?></span>
                    <?php if ($hasNextPage): ?><a class="button" href="<?= mg_h(page_link(["page" => $page + 1])) ?>#events">Older</a><?php endif; ?>
                </div>
            </section>

            <section class="panel" id="scans">
                <div class="panel-head">
                    <h2>Agent scans</h2>
                    <form method="get" action="devices.php#scans" class="form-row" style="min-width:320px;">
                        <div>
                            <select name="risk" aria-label="Filter by risk" onchange="this.form.submit()">
                                <option value="">All risk levels</option>
                                <?php foreach (["critical", "high", "medium", "low", "safe", "unknown", "not_scanned"] as $risk): ?>
                                    <option value="<?= $risk ?>"<?= $filterRisk === $risk ? " selected" : "" ?>><?= $risk === "not_scanned" ? "Not scanned (pending/failed)" : ucfirst($risk) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Requested</th><th>Computer</th><th>File</th><th>Status</th><th>Risk</th><th>Detection ratio</th><th>Requested by</th><th></th></tr></thead>
                        <tbody>
                        <?php if (!$scanRows): ?>
                            <tr><td class="empty" colspan="8">No agent scans yet. Use the Scan button next to a file event.</td></tr>
                        <?php endif; ?>
                        <?php foreach ($scanRows as $row): ?>
                            <tr>
                                <td><?= mg_h($row["created_at"]) ?></td>
                                <td><?= mg_h(($row["display_name"] ?: $row["hostname"]) ?: $row["device_id"]) ?></td>
                                <td><small><?= mg_h($row["file_path"]) ?></small></td>
                                <td><span class="badge <?= mg_h($row["status"]) ?>"><?= mg_h(ucfirst($row["status"])) ?></span>
                                    <?php if ($row["error_message"]): ?><br><small><?= mg_h($row["error_message"]) ?></small><?php endif; ?>
                                    <?php if ($row["status"] === "dispatched"): ?><br><small>Attempt <?= (int) $row["attempts"] ?> of 3</small><?php endif; ?></td>
                                <td><?= risk_badge($row["threat_level"]) ?></td>
                                <td><?= $row["vt_status"] === "found" ? mg_h($row["vt_malicious"] . "/" . $row["vt_engines"]) : ($row["scan_id"] ? '<small>' . mg_h(str_replace("_", " ", (string) $row["vt_status"])) . '</small>' : "—") ?></td>
                                <td><?= mg_h($row["requested_by_name"] ?? "Automatic") ?></td>
                                <td>
                                    <?php if ($row["scan_id"]): ?>
                                        <a class="button" href="<?= mg_h(page_link(["scan" => $row["scan_id"]])) ?>#scan-detail">Details</a>
                                    <?php elseif (in_array($row["status"], ["pending", "dispatched"], true)): ?>
                                        <form class="inline" method="post" action="devices.php">
                                            <?= hidden_fields($csrf, $returnQuery) ?>
                                            <input type="hidden" name="action" value="cancel_scan">
                                            <input type="hidden" name="request_id" value="<?= (int) $row["request_id"] ?>">
                                            <button type="submit" class="danger">Cancel</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </main>
    </div>
    <script>
        // Confirmation, rename prompt and "working" state for action buttons.
        document.querySelectorAll("form[method=post]").forEach(function (form) {
            form.addEventListener("submit", function (event) {
                const button = event.submitter || form.querySelector("button[type=submit]");
                if (button && button.dataset.confirm && !window.confirm(button.dataset.confirm)) {
                    event.preventDefault();
                    return;
                }
                if (button && button.dataset.rename !== undefined) {
                    const name = window.prompt("New name for this device:", button.dataset.rename);
                    if (name === null || name.trim() === "") {
                        event.preventDefault();
                        return;
                    }
                    form.querySelector("input[name=display_name]").value = name.trim();
                }
                if (button) {
                    button.disabled = true;
                    button.textContent = "Working...";
                }
            });
        });

        const copyButton = document.getElementById("copyToken");
        if (copyButton) {
            copyButton.addEventListener("click", function () {
                const text = document.getElementById("newToken").textContent.trim();
                navigator.clipboard.writeText(text).then(function () {
                    copyButton.textContent = "Copied";
                }, function () {
                    copyButton.textContent = "Select the token and press Ctrl+C";
                });
            });
        }

        // Live device status: refresh counts and statuses every 15 seconds.
        const liveStatus = document.getElementById("liveStatus");
        function refreshDevices() {
            liveStatus.textContent = "Refreshing...";
            liveStatus.classList.remove("error");
            fetch("devices.php?format=json", { headers: { "Accept": "application/json" }, credentials: "same-origin" })
                .then(function (response) {
                    if (!response.ok) throw new Error("server returned " + response.status);
                    return response.json();
                })
                .then(function (data) {
                    Object.entries(data.stats).forEach(function ([key, value]) {
                        const el = document.querySelector('[data-stat="' + key + '"]');
                        if (el) el.textContent = value;
                    });
                    data.devices.forEach(function (device) {
                        const row = document.querySelector('tr[data-device-id="' + CSS.escape(device.device_id) + '"]');
                        if (!row) return;
                        const badge = row.querySelector('[data-field="status"]');
                        badge.className = "badge " + device.status_class;
                        badge.textContent = device.status_label;
                        row.querySelector('[data-field="status-detail"]').textContent = device.status_detail;
                        row.querySelector('[data-field="heartbeat"]').textContent = device.last_heartbeat_at || "Never";
                        row.querySelector('[data-field="ip"]').textContent = device.ip_address || "—";
                    });
                    liveStatus.textContent = "Status updated " + new Date().toLocaleTimeString() + ".";
                })
                .catch(function (error) {
                    liveStatus.textContent = "Live status update failed (" + error.message + "). Reload the page.";
                    liveStatus.classList.add("error");
                });
        }
        setInterval(refreshDevices, 15000);
    </script>
</body>
</html>
