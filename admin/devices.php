<?php
// Device screens. ?view= selects the screen:
//   computers  registered computers and their status (default)
//   tokens     "Add a computer": enrollment tokens and setup steps
//   events     file events reported by agents, with filters and Scan buttons
//   scans      scans requested from agents, and scan details (?scan=ID)
// Admins and verified super admins only.

require_once __DIR__ . "/../includes/scan_detail.php";

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

// Returns to the screen the form was on, keeping its filters.
function redirect_back(string $notice, bool $isError = false, string $anchor = ""): never
{
    $_SESSION["devices_notice"] = [$notice, $isError];
    parse_str(is_string($_POST["return_query"] ?? null) ? $_POST["return_query"] : "", $query);
    $fallback = ["#tokens" => "tokens", "#devices" => "computers", "#events" => "events", "#scans" => "scans"];
    $query["view"] ??= $fallback[$anchor] ?? "computers";
    header("Location: devices.php?" . http_build_query($query));
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

    if ($action === "rename_token") {
        $id = filter_var($_POST["token_id"] ?? "", FILTER_VALIDATE_INT) ?: 0;
        $label = post_string("label", 100);
        if ($label === "") {
            redirect_back("Enter a label for the token.", true, "#tokens");
        }
        $stmt = $pdo->prepare("UPDATE enrollment_tokens SET label = ? WHERE id = ?");
        $stmt->execute([$label, $id]);
        mg_audit("user", $actorId, "token.renamed", "token:" . $id, ["label" => $label]);
        redirect_back("Token renamed.", false, "#tokens");
    }

    if ($action === "delete_token") {
        // Deleting removes only the token record; a device that already
        // enrolled with it keeps working, and the audit log keeps the history.
        $id = filter_var($_POST["token_id"] ?? "", FILTER_VALIDATE_INT) ?: 0;
        $stmt = $pdo->prepare("DELETE FROM enrollment_tokens WHERE id = ?");
        $stmt->execute([$id]);
        if ($stmt->rowCount() === 0) {
            redirect_back("That token no longer exists.", true, "#tokens");
        }
        mg_audit("user", $actorId, "token.deleted", "token:" . $id);
        redirect_back("Token deleted.", false, "#tokens");
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
| Screen selection and live status
|--------------------------------------------------------------------------
*/

$views = ["computers", "tokens", "events", "scans"];
$view = is_string($_GET["view"] ?? null) && in_array($_GET["view"], $views, true) ? $_GET["view"] : "computers";
if (isset($_GET["scan"])) {
    $view = "scans";
}

$stats = mg_device_summary($pdo);
$awaiting = (int) $pdo->query("SELECT COUNT(*) FROM enrollment_tokens WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()")->fetchColumn();

if (($_GET["format"] ?? "") === "json") {
    header("Content-Type: application/json");
    header("Cache-Control: no-store");
    $devicesJson = [];
    foreach ($pdo->query("SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d")->fetchAll() as $row) {
        [$class, $label, $explain] = mg_device_status($row);
        $devicesJson[] = [
            "device_id" => $row["device_id"],
            "status_class" => $class,
            "status_label" => $label,
            "status_detail" => $explain,
            "last_heartbeat_at" => $row["last_heartbeat_at"],
            "ip_address" => $row["ip_address"],
        ];
    }
    echo json_encode([
        "ok" => true,
        "stats" => ["total" => $stats["total"], "online" => $stats["online"], "offline" => $stats["offline"], "awaiting" => $awaiting],
        "devices" => $devicesJson,
    ]);
    exit;
}

$notice = $_SESSION["devices_notice"] ?? null;
$newToken = $_SESSION["devices_new_token"] ?? null;
unset($_SESSION["devices_notice"], $_SESSION["devices_new_token"]);

$filterDevice = is_string($_GET["device"] ?? null) ? $_GET["device"] : "";
$filterType = is_string($_GET["type"] ?? null) ? $_GET["type"] : "";
$filterQuery = is_string($_GET["q"] ?? null) ? mb_substr(trim($_GET["q"]), 0, 200) : "";
$filterDownloads = ($_GET["downloads"] ?? "") === "1";
$filterRisk = is_string($_GET["risk"] ?? null) ? $_GET["risk"] : "";
$page = max(1, (int) ($_GET["page"] ?? 1));

$returnQuery = http_build_query(array_filter([
    "view" => $view, "device" => $filterDevice, "type" => $filterType, "q" => $filterQuery,
    "downloads" => $filterDownloads ? "1" : "", "risk" => $filterRisk, "page" => $page > 1 ? $page : "",
], static fn ($v) => $v !== "" && $v !== null));

function page_link(array $overrides): string
{
    global $view, $filterDevice, $filterType, $filterQuery, $filterDownloads, $filterRisk;
    $query = array_merge([
        "view" => $view, "device" => $filterDevice, "type" => $filterType, "q" => $filterQuery,
        "downloads" => $filterDownloads ? "1" : "", "risk" => $filterRisk,
    ], $overrides);
    return "devices.php?" . http_build_query(array_filter($query, static fn ($v) => $v !== "" && $v !== null));
}

function hidden_fields(string $csrf, string $returnQuery): string
{
    return '<input type="hidden" name="csrf_token" value="' . mg_h($csrf) . '">'
        . '<input type="hidden" name="return_query" value="' . mg_h($returnQuery) . '">';
}

$addButton = '<a class="button primary" href="devices.php?view=tokens"><i class="fa-solid fa-plus" aria-hidden="true"></i>Add a computer</a>';

/*
|--------------------------------------------------------------------------
| Computers
|--------------------------------------------------------------------------
*/

if ($view === "computers") {
    $devices = $pdo->query(
        "SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d
         ORDER BY FIELD(d.status, 'active', 'legacy', 'revoked'), d.last_heartbeat_at IS NULL, d.last_heartbeat_at DESC, d.id DESC"
    )->fetchAll();

    mg_admin_page_start($admin, "computers", "Computers",
        'Computers running the MalwareGuard agent. A computer is <strong>Online</strong> while its agent keeps checking in. <span class="live-status" id="liveStatus" role="status" aria-live="polite"></span>',
        $addButton);
    mg_admin_notice($notice);
    ?>
    <section class="stats" aria-label="Computer summary">
        <div class="stat"><span>Registered</span><strong data-stat="total"><?= $stats["total"] ?></strong></div>
        <div class="stat ok"><span>Online</span><strong data-stat="online"><?= $stats["online"] ?></strong></div>
        <div class="stat"><span>Offline</span><strong data-stat="offline"><?= $stats["offline"] ?></strong></div>
        <a class="stat warn" href="devices.php?view=tokens"><span>Waiting to join</span><strong data-stat="awaiting"><?= $awaiting ?></strong><small>Unused tokens</small></a>
    </section>
    <section class="panel">
        <?php if (!$devices): ?>
            <?php mg_admin_empty("fa-desktop", "No computers yet", "Add your first computer: generate a token, then run the installer on that PC. It takes about 5 minutes.", $addButton); ?>
        <?php else: ?>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Computer</th><th>Status</th><th>IP address</th><th>Last check-in</th><th>Watching</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($devices as $device): ?>
                    <?php [$statusClass, $statusLabel, $statusDetail] = mg_device_status($device); ?>
                    <?php $paths = json_decode((string) $device["monitored_paths"], true); ?>
                    <tr data-device-id="<?= mg_h($device["device_id"]) ?>">
                        <td>
                            <strong><?= mg_h(mg_device_label($device)) ?></strong><br>
                            <small><?= mg_h($device["os_name"] ?: "—") ?></small><br>
                            <small>Agent <?= mg_h($device["agent_version"] ?: "—") ?> · added <?= mg_h(substr((string) ($device["registered_at"] ?: $device["created_at"]), 0, 10)) ?></small>
                        </td>
                        <td>
                            <span class="badge <?= mg_h($statusClass) ?>" data-field="status"><?= mg_h($statusLabel) ?></span><br>
                            <small data-field="status-detail"><?= mg_h($statusDetail) ?></small>
                            <?php if ($device["rotate_requested"] || $device["pending_credential_hash"]): ?><br><small>Key change in progress</small><?php endif; ?>
                        </td>
                        <td data-field="ip"><?= mg_h($device["ip_address"] ?: "—") ?></td>
                        <td data-field="heartbeat"><?= mg_h($device["last_heartbeat_at"] ?: "Never") ?></td>
                        <td><small><?= is_array($paths) && $paths ? mg_h(implode(", ", $paths)) : "—" ?></small></td>
                        <td>
                            <?php if ($device["status"] === "active"): ?>
                            <div class="actions">
                                <a class="button small ghost" href="devices.php?view=events&amp;device=<?= urlencode($device["device_id"]) ?>"><i class="fa-solid fa-file-arrow-down" aria-hidden="true"></i>Files</a>
                                <form class="inline" method="post" action="devices.php">
                                    <?= hidden_fields($csrf, $returnQuery) ?>
                                    <input type="hidden" name="action" value="rename_device">
                                    <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                    <input type="hidden" name="display_name" value="" data-rename-target>
                                    <button type="submit" class="small" data-rename="<?= mg_h(mg_device_label($device)) ?>" data-rename-prompt="New name for this computer:"><i class="fa-solid fa-pen" aria-hidden="true"></i>Rename</button>
                                </form>
                                <form class="inline" method="post" action="devices.php">
                                    <?= hidden_fields($csrf, $returnQuery) ?>
                                    <input type="hidden" name="action" value="rotate_credential">
                                    <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                    <button type="submit" class="small" data-confirm="Give this computer a new secret key? It switches automatically on its next check-in."><i class="fa-solid fa-rotate" aria-hidden="true"></i>New key</button>
                                </form>
                                <form class="inline" method="post" action="devices.php">
                                    <?= hidden_fields($csrf, $returnQuery) ?>
                                    <input type="hidden" name="action" value="revoke_device">
                                    <input type="hidden" name="device_id" value="<?= mg_h($device["device_id"]) ?>">
                                    <button type="submit" class="small danger" data-confirm="Remove <?= mg_h(mg_device_label($device)) ?>? Its agent will be refused until it is added again with a new token."><i class="fa-solid fa-ban" aria-hidden="true"></i>Remove</button>
                                </form>
                            </div>
                            <?php else: ?>
                                <small>To use it again, <a href="devices.php?view=tokens">add it again</a> with a new token.</small>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </section>
    <?php
    $script = <<<'HTML'
    <script>
        // Refresh counts and statuses every 15 seconds.
        const liveStatus = document.getElementById("liveStatus");
        function refreshDevices() {
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
                    liveStatus.classList.remove("error");
                    liveStatus.textContent = "Updated " + new Date().toLocaleTimeString() + ".";
                })
                .catch(function (error) {
                    liveStatus.textContent = "Live update failed (" + error.message + "). Reload the page.";
                    liveStatus.classList.add("error");
                });
        }
        setInterval(refreshDevices, 15000);
    </script>
HTML;
    mg_admin_page_end($script);
    exit;
}

/*
|--------------------------------------------------------------------------
| Add a computer (enrollment tokens)
|--------------------------------------------------------------------------
*/

if ($view === "tokens") {
    $tokens = $pdo->query(
        "SELECT t.id, t.token_hint, t.label, t.created_at, t.expires_at, t.used_at, t.used_by_device, t.revoked_at,
                t.expires_at <= NOW() AS expired, u.name AS created_by_name, d.display_name AS device_name
         FROM enrollment_tokens t
         LEFT JOIN users u ON u.id = t.created_by
         LEFT JOIN endpoint_devices d ON d.device_id = t.used_by_device
         ORDER BY t.id DESC LIMIT 25"
    )->fetchAll();
    $serverHost = $_SERVER["HTTP_HOST"] ?? "SERVER-IP:8000";
    $scheme = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") ? "https" : "http";
    // Includes the folder when the app lives in a subfolder (XAMPP: /maliciousproject).
    $basePath = rtrim(str_replace("\\", "/", dirname(dirname($_SERVER["SCRIPT_NAME"] ?? "/admin/devices.php"))), "/");
    $serverUrl = $scheme . "://" . $serverHost . $basePath;
    $isLocalOnly = str_starts_with($serverHost, "127.0.0.1") || str_starts_with($serverHost, "localhost");
    $defaultTtl = mg_setting_int("ENROLLMENT_TOKEN_TTL_HOURS", 24, 1, 168);

    mg_admin_page_start($admin, "tokens", "Add a computer", "Each computer needs its own one-time token. Follow the three steps below.");
    mg_admin_notice($notice);
    ?>
    <?php if ($newToken): ?>
        <div class="token-box" role="alert">
            <strong><i class="fa-solid fa-key" aria-hidden="true"></i> Token for "<?= mg_h($newToken["label"]) ?>"</strong>
            <small> · works once · expires in <?= (int) $newToken["hours"] ?> h · copy it now, it will not be shown again</small>
            <code class="token" id="newToken"><?= mg_h($newToken["token"]) ?></code>
            <button type="button" class="primary" id="copyToken"><i class="fa-solid fa-copy" aria-hidden="true"></i>Copy token</button>
        </div>
    <?php endif; ?>

    <div class="grid-2">
        <section class="panel">
            <div class="panel-head"><div><h2>1. Generate a token</h2><p>Name it after the computer so you recognise it later.</p></div></div>
            <form method="post" action="devices.php" style="display:grid;gap:14px;">
                <?= hidden_fields($csrf, $returnQuery) ?>
                <input type="hidden" name="action" value="create_token">
                <div><label for="token-label">Computer name</label><input id="token-label" name="label" maxlength="100" placeholder="Lab PC 04" required></div>
                <div><label for="token-ttl">Valid for (hours)</label><input id="token-ttl" name="ttl_hours" type="number" min="1" max="168" value="<?= $defaultTtl ?>" required></div>
                <div><button type="submit" class="primary"><i class="fa-solid fa-key" aria-hidden="true"></i>Generate token</button></div>
            </form>
        </section>
        <section class="panel">
            <div class="panel-head"><div><h2>2. Install the agent on that computer</h2><p>Do this on the computer you want to monitor.</p></div></div>
            <ol class="steps">
                <li>Install <strong>Python</strong> and tick <strong>"Add python.exe to PATH"</strong>.</li>
                <li>Copy the project's <strong>agent</strong> folder to that computer.</li>
                <li>Double-click <strong>INSTALL_AGENT.bat</strong> and enter:
                    <br>Server address: <code><?= mg_h($serverUrl) ?></code>
                    <br>Token: the token from step 1</li>
            </ol>
            <?php if ($isLocalOnly): ?>
                <p class="hint" style="margin-top:12px;"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> This address only works on this PC. Other computers need this PC's IP instead of <code>localhost</code>, for example <code>http://10.83.54.4<?= mg_h($basePath) ?></code> (find the IP with <code>ipconfig</code>). Open the dashboard through that IP and this page shows the exact address.</p>
            <?php endif; ?>
            <p class="hint" style="margin-top:12px;"><strong>3.</strong> The computer appears under <a href="devices.php?view=computers">Computers</a> as <strong>Online</strong>.</p>
        </section>
    </div>

    <section class="panel" style="margin-top:24px;">
        <div class="panel-head"><div><h2>Tokens</h2><p>Unused tokens can be revoked. Deleting a used token does not remove its computer.</p></div></div>
        <?php if (!$tokens): ?>
            <?php mg_admin_empty("fa-key", "No tokens yet", "Generate a token above to add your first computer."); ?>
        <?php else: ?>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Name</th><th>State</th><th>Created</th><th>Expires</th><th>Used by</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($tokens as $token): ?>
                    <?php
                    if ($token["used_at"] !== null) { [$tc, $tl] = ["completed", "Used"]; }
                    elseif ($token["revoked_at"] !== null) { [$tc, $tl] = ["revoked", "Revoked"]; }
                    elseif ($token["expired"]) { [$tc, $tl] = ["expired", "Expired"]; }
                    else { [$tc, $tl] = ["awaiting", "Waiting to be used"]; }
                    ?>
                    <tr>
                        <td><strong><?= mg_h($token["label"]) ?></strong><br><small><code><?= mg_h($token["token_hint"]) ?>…</code> · by <?= mg_h($token["created_by_name"] ?? "unknown") ?></small></td>
                        <td><span class="badge <?= $tc ?>"><?= $tl ?></span></td>
                        <td><?= mg_h($token["created_at"]) ?></td>
                        <td><?= mg_h($token["expires_at"]) ?></td>
                        <td><?= $token["used_by_device"] ? mg_h($token["device_name"] ?: $token["used_by_device"]) . "<br><small>" . mg_h($token["used_at"]) . "</small>" : "—" ?></td>
                        <td>
                            <div class="actions">
                                <form class="inline" method="post" action="devices.php">
                                    <?= hidden_fields($csrf, $returnQuery) ?>
                                    <input type="hidden" name="action" value="rename_token">
                                    <input type="hidden" name="token_id" value="<?= (int) $token["id"] ?>">
                                    <input type="hidden" name="label" value="" data-rename-target>
                                    <button type="submit" class="small" data-rename="<?= mg_h($token["label"]) ?>" data-rename-prompt="New name for this token:"><i class="fa-solid fa-pen" aria-hidden="true"></i>Rename</button>
                                </form>
                                <?php if ($tc === "awaiting"): ?>
                                    <form class="inline" method="post" action="devices.php">
                                        <?= hidden_fields($csrf, $returnQuery) ?>
                                        <input type="hidden" name="action" value="revoke_token">
                                        <input type="hidden" name="token_id" value="<?= (int) $token["id"] ?>">
                                        <button type="submit" class="small danger"><i class="fa-solid fa-ban" aria-hidden="true"></i>Revoke</button>
                                    </form>
                                <?php endif; ?>
                                <form class="inline" method="post" action="devices.php">
                                    <?= hidden_fields($csrf, $returnQuery) ?>
                                    <input type="hidden" name="action" value="delete_token">
                                    <input type="hidden" name="token_id" value="<?= (int) $token["id"] ?>">
                                    <button type="submit" class="small danger" data-confirm="Delete the token &quot;<?= mg_h($token["label"]) ?>&quot;?<?= $tc === "awaiting" ? " It can no longer be used to add a computer." : "" ?><?= $tc === "completed" ? " The computer that used it stays registered." : "" ?>"><i class="fa-solid fa-trash" aria-hidden="true"></i>Delete</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </section>
    <?php
    $script = <<<'HTML'
    <script>
        const copyButton = document.getElementById("copyToken");
        if (copyButton) {
            copyButton.addEventListener("click", function () {
                const text = document.getElementById("newToken").textContent.trim();
                navigator.clipboard.writeText(text).then(function () {
                    copyButton.innerHTML = '<i class="fa-solid fa-check" aria-hidden="true"></i> Copied';
                }, function () {
                    copyButton.textContent = "Select the token and press Ctrl+C";
                });
            });
        }
    </script>
HTML;
    mg_admin_page_end($script);
    exit;
}

/*
|--------------------------------------------------------------------------
| File events
|--------------------------------------------------------------------------
*/

if ($view === "events") {
    $perPage = 50;
    $where = [];
    $params = [];
    if ($filterDevice !== "") {
        $where[] = "e.device_id = ?";
        $params[] = $filterDevice;
    }
    if (in_array($filterType, ["created", "modified", "renamed", "moved", "deleted"], true)) {
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
    $stmt = $pdo->prepare(
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
    $stmt->execute($params);
    $events = $stmt->fetchAll();
    $hasNextPage = count($events) > $perPage;
    $events = array_slice($events, 0, $perPage);
    $deviceOptions = $pdo->query("SELECT device_id, display_name, hostname FROM endpoint_devices ORDER BY display_name")->fetchAll();
    $eventIcons = ["created" => "fa-file-circle-plus", "modified" => "fa-file-pen", "renamed" => "fa-i-cursor", "moved" => "fa-file-export", "deleted" => "fa-file-circle-xmark"];

    mg_admin_page_start($admin, "events", "File events",
        "Files that appeared, changed, moved or were deleted in the watched folders (usually Downloads). Click <strong>Scan</strong> to check a file; the computer sends it to this server and only its hash goes to VirusTotal.");
    mg_admin_notice($notice);
    ?>
    <section class="panel">
        <form method="get" action="devices.php" class="form-row toolbar">
            <input type="hidden" name="view" value="events">
            <div><label for="f-q">Search</label><input id="f-q" name="q" type="search" value="<?= mg_h($filterQuery) ?>" placeholder="File name, path or hash"></div>
            <div><label for="f-device">Computer</label>
                <select id="f-device" name="device">
                    <option value="">All computers</option>
                    <?php foreach ($deviceOptions as $option): ?>
                        <option value="<?= mg_h($option["device_id"]) ?>"<?= $filterDevice === $option["device_id"] ? " selected" : "" ?>><?= mg_h(($option["display_name"] ?: $option["hostname"]) ?: $option["device_id"]) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div><label for="f-type">What happened</label>
                <select id="f-type" name="type">
                    <option value="">Anything</option>
                    <?php foreach (["created" => "New file", "modified" => "Changed", "renamed" => "Renamed", "moved" => "Moved", "deleted" => "Deleted"] as $type => $label): ?>
                        <option value="<?= $type ?>"<?= $filterType === $type ? " selected" : "" ?>><?= $label ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div><label class="check"><input type="checkbox" name="downloads" value="1"<?= $filterDownloads ? " checked" : "" ?>> Downloads only</label></div>
            <div class="actions"><button type="submit"><i class="fa-solid fa-filter" aria-hidden="true"></i>Filter</button><a class="button ghost" href="devices.php?view=events">Clear</a></div>
        </form>

        <?php if (!$events): ?>
            <?php if ($where): ?>
                <?php mg_admin_empty("fa-filter", "Nothing matches these filters", "Try a different search or clear the filters.", '<a class="button" href="devices.php?view=events">Clear filters</a>'); ?>
            <?php elseif ($stats["total"] === 0): ?>
                <?php mg_admin_empty("fa-desktop", "No computers yet", "File events appear once a computer runs the agent.", $addButton); ?>
            <?php else: ?>
                <?php mg_admin_empty("fa-file-arrow-down", "No file events yet", "Download any file on a monitored computer. It appears here within a few seconds. Files that were already there are not listed."); ?>
            <?php endif; ?>
        <?php else: ?>
        <div class="table-wrap">
            <table>
                <thead><tr><th>When</th><th>File</th><th>Computer</th><th>What happened</th><th>Size</th><th>Scan</th></tr></thead>
                <tbody>
                <?php foreach ($events as $event): ?>
                    <tr>
                        <td title="Detected: <?= mg_h($event["detected_at"] ?: $event["occurred_at"]) ?>&#10;Received by server: <?= mg_h($event["received_at"]) ?>"><?= mg_h($event["occurred_at"]) ?></td>
                        <td>
                            <?php $previousName = $event["previous_path"] ? basename(str_replace("\\", "/", $event["previous_path"])) : ""; ?>
                            <?php if ($previousName !== "" && in_array($event["event_type"], ["renamed", "moved"], true)): ?>
                                <strong><?= mg_h($previousName) ?> &rarr; <?= mg_h($event["file_name"]) ?></strong><br>
                            <?php else: ?>
                                <strong><?= mg_h($event["file_name"]) ?></strong><br>
                            <?php endif; ?>
                            <small title="<?= mg_h($event["sha256"] ?? "") ?>"><?= mg_h($event["file_path"]) ?></small>
                            <?php if ($event["previous_path"] && $event["event_type"] === "moved"): ?><br><small>from <?= mg_h($event["previous_path"]) ?></small><?php endif; ?>
                        </td>
                        <td>
                            <?= mg_h(($event["display_name"] ?: $event["hostname"]) ?: $event["device_id"]) ?>
                            <?php if (!empty($event["user_account"])): ?><br><small><i class="fa-solid fa-user" aria-hidden="true"></i> <?= mg_h($event["user_account"]) ?></small><?php endif; ?>
                        </td>
                        <td>
                            <i class="fa-solid <?= $eventIcons[$event["event_type"]] ?? "fa-file" ?>" aria-hidden="true"></i>
                            <?= mg_h(["created" => "New file", "modified" => "Changed", "renamed" => "Renamed", "moved" => "Moved", "deleted" => "Deleted"][$event["event_type"]] ?? $event["event_type"]) ?>
                            <?php if ($event["is_potential_download"]): ?><br><small>Download</small><?php endif; ?>
                        </td>
                        <td><?= mg_h(mg_format_bytes($event["file_size"] === null ? null : (int) $event["file_size"])) ?></td>
                        <td>
                            <?php if ($event["scan_id"]): ?>
                                <a href="devices.php?view=scans&amp;scan=<?= (int) $event["scan_id"] ?>"><?= mg_risk_badge($event["scan_threat"]) ?></a>
                            <?php elseif (in_array($event["request_status"], ["pending", "dispatched"], true)): ?>
                                <span class="badge pending"><i class="fa-solid fa-hourglass-half" aria-hidden="true"></i>Waiting</span><br><small>Runs on the computer's next check-in</small>
                            <?php else: ?>
                                <?php if ($event["request_status"] === "failed"): ?>
                                    <span class="badge failed">Scan failed</span><br><small><?= mg_h($event["request_error"]) ?></small><br>
                                <?php elseif ($event["hash_scan_id"]): ?>
                                    <small>Same file checked before:</small>
                                    <a href="devices.php?view=scans&amp;scan=<?= (int) $event["hash_scan_id"] ?>"><?= mg_risk_badge($event["hash_scan_threat"]) ?></a><br>
                                <?php endif; ?>
                                <?php if ($event["event_type"] !== "deleted" && $event["device_status"] === "active"): ?>
                                    <form class="inline" method="post" action="devices.php">
                                        <?= hidden_fields($csrf, $returnQuery) ?>
                                        <input type="hidden" name="action" value="request_scan">
                                        <input type="hidden" name="event_id" value="<?= (int) $event["id"] ?>">
                                        <button type="submit" class="small primary" style="margin-top:4px;"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Scan</button>
                                    </form>
                                <?php elseif (!$event["hash_scan_id"] && $event["request_status"] !== "failed"): ?>
                                    <small>—</small>
                                <?php endif; ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="pager">
            <?php if ($page > 1): ?><a class="button small ghost" href="<?= mg_h(page_link(["page" => $page - 1])) ?>"><i class="fa-solid fa-chevron-left" aria-hidden="true"></i>Newer</a><?php endif; ?>
            <span>Page <?= $page ?></span>
            <?php if ($hasNextPage): ?><a class="button small ghost" href="<?= mg_h(page_link(["page" => $page + 1])) ?>">Older<i class="fa-solid fa-chevron-right" aria-hidden="true"></i></a><?php endif; ?>
        </div>
        <?php endif; ?>
    </section>
    <?php
    mg_admin_page_end();
    exit;
}

/*
|--------------------------------------------------------------------------
| Agent scans
|--------------------------------------------------------------------------
*/

$scanWhere = "";
$scanParams = [];
if (in_array($filterRisk, ["safe", "low", "medium", "high", "critical", "unknown"], true)) {
    $scanWhere = "WHERE s.threat_level = ?";
    $scanParams[] = $filterRisk;
} elseif ($filterRisk === "not_scanned") {
    $scanWhere = "WHERE sr.scan_id IS NULL";
}
$stmt = $pdo->prepare(
    "SELECT sr.id AS request_id, sr.status, sr.file_path, sr.error_message, sr.created_at, sr.attempts,
            d.display_name, d.hostname, d.device_id, u.name AS requested_by_name,
            s.id AS scan_id, s.threat_level, s.vt_status, s.vt_malicious, s.vt_engines
     FROM scan_requests sr
     JOIN endpoint_devices d ON d.device_id = sr.device_id
     LEFT JOIN users u ON u.id = sr.requested_by
     LEFT JOIN scans s ON s.id = sr.scan_id
     $scanWhere
     ORDER BY sr.id DESC LIMIT 50"
);
$stmt->execute($scanParams);
$scanRows = $stmt->fetchAll();
$detailId = filter_var($_GET["scan"] ?? "", FILTER_VALIDATE_INT);

mg_admin_page_start($admin, "scans", "Agent scans", "Scans of files on monitored computers. A scan waits until the computer checks in (about 30 seconds), then the result appears here.");
mg_admin_notice($notice);
if ($detailId && !mg_render_scan_detail($pdo, (int) $detailId, page_link(["scan" => null]))) {
    mg_admin_notice(["That scan was not found.", true]);
}
?>
<section class="panel">
    <form method="get" action="devices.php" class="form-row toolbar" style="max-width:360px;">
        <input type="hidden" name="view" value="scans">
        <div><label for="risk">Show</label>
            <select id="risk" name="risk" onchange="this.form.submit()">
                <option value="">All scans</option>
                <?php foreach (["critical" => "Critical", "high" => "High", "medium" => "Medium", "low" => "Low", "safe" => "Safe", "unknown" => "Unknown", "not_scanned" => "Waiting or failed"] as $risk => $label): ?>
                    <option value="<?= $risk ?>"<?= $filterRisk === $risk ? " selected" : "" ?>><?= $label ?></option>
                <?php endforeach; ?>
            </select>
        </div>
    </form>
    <?php if (!$scanRows): ?>
        <?php mg_admin_empty("fa-magnifying-glass", $filterRisk !== "" ? "No scans match this filter" : "No agent scans yet", "Open File events and click Scan next to a file.", '<a class="button primary" href="devices.php?view=events"><i class="fa-solid fa-file-arrow-down" aria-hidden="true"></i>Open file events</a>'); ?>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead><tr><th>Requested</th><th>File</th><th>Computer</th><th>Status</th><th>Risk</th><th>VirusTotal</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($scanRows as $row): ?>
                <tr>
                    <td><?= mg_h($row["created_at"]) ?><br><small>by <?= mg_h($row["requested_by_name"] ?? "automatic scan") ?></small></td>
                    <td><strong><?= mg_h(basename(str_replace("\\", "/", $row["file_path"]))) ?></strong><br><small><?= mg_h($row["file_path"]) ?></small></td>
                    <td><?= mg_h(($row["display_name"] ?: $row["hostname"]) ?: $row["device_id"]) ?></td>
                    <td>
                        <span class="badge <?= mg_h($row["status"]) ?>"><?= mg_h(["pending" => "Waiting", "dispatched" => "Sent to computer", "completed" => "Done", "failed" => "Failed", "cancelled" => "Cancelled"][$row["status"]] ?? $row["status"]) ?></span>
                        <?php if ($row["error_message"]): ?><br><small><?= mg_h($row["error_message"]) ?></small><?php endif; ?>
                        <?php if ($row["status"] === "dispatched"): ?><br><small>Attempt <?= (int) $row["attempts"] ?> of 3</small><?php endif; ?>
                    </td>
                    <td><?= $row["scan_id"] ? mg_risk_badge($row["threat_level"]) : "<small>—</small>" ?></td>
                    <td><?= $row["vt_status"] === "found" ? mg_h($row["vt_malicious"] . "/" . $row["vt_engines"]) : "<small>—</small>" ?></td>
                    <td>
                        <?php if ($row["scan_id"]): ?>
                            <a class="button small" href="<?= mg_h(page_link(["scan" => $row["scan_id"]])) ?>">Details</a>
                        <?php elseif (in_array($row["status"], ["pending", "dispatched"], true)): ?>
                            <form class="inline" method="post" action="devices.php">
                                <?= hidden_fields($csrf, $returnQuery) ?>
                                <input type="hidden" name="action" value="cancel_scan">
                                <input type="hidden" name="request_id" value="<?= (int) $row["request_id"] ?>">
                                <button type="submit" class="small danger">Cancel</button>
                            </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</section>
<?php
mg_admin_page_end();
