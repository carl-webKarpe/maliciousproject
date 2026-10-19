<?php
// Admin home and scanning screens. ?view= selects the screen:
//   (none)      Dashboard: numbers, getting started, recent threats and downloads
//   scanner     Upload a file for analysis (upload.php redirects back here with ?scan_id=)
//   history     Every scan, uploads and agent scans
//   threats     Scans with suspicious or worse results
//   quarantine  Uploaded files kept in quarantine
//   settings    Change your password

require_once __DIR__ . "/../includes/scan_detail.php";

$admin = mg_require_admin_session();
if (!$admin) {
    header("Location: login.html");
    exit;
}

try {
    $pdo = mg_pdo();
} catch (Throwable $e) {
    error_log("Admin dashboard database error: " . $e->getMessage());
    http_response_code(503);
    exit("The database is unavailable. Check that the MySQL Server service is running.");
}

$csrf = $_SESSION["admin_settings_csrf"] ??= bin2hex(random_bytes(32));
$views = ["home", "scanner", "history", "threats", "quarantine", "settings"];
$view = is_string($_GET["view"] ?? null) && in_array($_GET["view"], $views, true) ? $_GET["view"] : "home";
$uploadedScanId = filter_input(INPUT_GET, "scan_id", FILTER_VALIDATE_INT) ?: 0;
if ($uploadedScanId > 0) {
    $view = "scanner"; // upload.php sends admins back here after a scan
}

/*
|--------------------------------------------------------------------------
| Change password
|--------------------------------------------------------------------------
*/

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $read = static fn (string $key): string => is_string($_POST[$key] ?? null) ? $_POST[$key] : "";
    $notice = ["", false];

    if ($read("action") !== "change_password") {
        http_response_code(400);
        exit("Invalid settings request.");
    }
    if (!hash_equals($csrf, $read("csrf_token"))) {
        $notice = ["The form expired. Reload the page and try again.", true];
    } elseif (strlen($read("new_password")) < 12) {
        $notice = ["New passwords must be at least 12 characters.", true];
    } elseif ($read("new_password") !== $read("confirm_password")) {
        $notice = ["The new password confirmation does not match.", true];
    } else {
        $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ? AND role = ? AND status = 'active' LIMIT 1");
        $stmt->execute([$admin["id"], $admin["role"]]);
        $account = $stmt->fetch();
        if (!$account || !password_verify($read("current_password"), $account["password"])) {
            $notice = ["Current password is incorrect.", true];
        } else {
            $pdo->prepare("UPDATE users SET password = ? WHERE id = ? AND role = ?")
                ->execute([password_hash($read("new_password"), PASSWORD_DEFAULT), $admin["id"], $admin["role"]]);
            session_regenerate_id(true);
            mg_audit("user", (string) $admin["id"], "account.password_changed");
            $notice = ["Password updated successfully.", false];
        }
    }

    $_SESSION["admin_notice"] = $notice;
    header("Location: dashboard.php?view=settings");
    exit;
}

$notice = $_SESSION["admin_notice"] ?? null;
unset($_SESSION["admin_notice"]);

/*
|--------------------------------------------------------------------------
| Shared scan list query
|--------------------------------------------------------------------------
*/

function scan_rows(PDO $pdo, string $where, array $params, int $limit = 100): array
{
    $stmt = $pdo->prepare(
        "SELECT s.id, s.original_file_name, s.file_size, s.detection_status, s.threat_level, s.security_score,
                s.scanned_at, s.scan_source, s.vt_status, s.vt_malicious, s.vt_engines, s.file_path,
                u.name AS uploader, u.email AS uploader_email, d.display_name, d.hostname, s.device_id
         FROM scans s
         LEFT JOIN users u ON u.id = s.user_id
         LEFT JOIN endpoint_devices d ON d.device_id = s.device_id
         " . ($where !== "" ? "WHERE $where" : "") . "
         ORDER BY s.id DESC LIMIT $limit"
    );
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function scan_source_label(array $row): string
{
    if ($row["device_id"] !== null) {
        return '<i class="fa-solid fa-desktop" aria-hidden="true"></i> ' . mg_h(($row["display_name"] ?: $row["hostname"]) ?: $row["device_id"]);
    }
    return '<i class="fa-solid fa-upload" aria-hidden="true"></i> ' . mg_h($row["uploader"] ?? "Unknown user");
}

function render_scan_table(array $rows, string $view, string $emptyIcon, string $emptyTitle, string $emptyText): void
{
    if (!$rows) {
        mg_admin_empty($emptyIcon, $emptyTitle, $emptyText, '<a class="button primary" href="dashboard.php?view=scanner"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Scan a file</a>');
        return;
    }
    ?>
    <div class="table-wrap">
        <table>
            <thead><tr><th>Scanned</th><th>File</th><th>Source</th><th>Risk</th><th>VirusTotal</th><th>Score</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($rows as $row): ?>
                <tr>
                    <td><?= mg_h($row["scanned_at"]) ?></td>
                    <td><strong><?= mg_h($row["original_file_name"]) ?></strong><br><small><?= mg_h(mg_format_bytes((int) $row["file_size"])) ?></small></td>
                    <td><?= scan_source_label($row) ?></td>
                    <td><?= mg_risk_badge($row["threat_level"]) ?></td>
                    <td><?= $row["vt_status"] === "found" ? mg_h($row["vt_malicious"] . "/" . $row["vt_engines"]) : "<small>—</small>" ?></td>
                    <td><?= (int) $row["security_score"] ?>/100</td>
                    <td><a class="button small" href="dashboard.php?view=<?= mg_h($view) ?>&amp;scan=<?= (int) $row["id"] ?>#scan-detail">Details</a></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php
}

$detailId = filter_input(INPUT_GET, "scan", FILTER_VALIDATE_INT) ?: 0;
$threatWhere = "(s.threat_level IN ('medium', 'high', 'critical') OR s.detection_status = 'malicious')";

/*
|--------------------------------------------------------------------------
| Screens
|--------------------------------------------------------------------------
*/

if ($view === "home") {
    $counts = $pdo->query(
        "SELECT
            (SELECT COUNT(*) FROM scans) AS scans,
            (SELECT COUNT(*) FROM scans s WHERE $threatWhere) AS threats,
            (SELECT COUNT(*) FROM file_events WHERE is_potential_download = 1 AND occurred_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS new_files,
            (SELECT COUNT(*) FROM file_events) AS all_events,
            (SELECT COUNT(*) FROM scan_requests WHERE status IN ('pending', 'dispatched')) AS pending"
    )->fetch();
    $devices = mg_device_summary($pdo);
    $recentThreats = scan_rows($pdo, $threatWhere, [], 5);
    $recentDownloads = $pdo->query(
        "SELECT e.file_name, e.file_path, e.occurred_at, d.display_name, d.hostname, e.device_id
         FROM file_events e JOIN endpoint_devices d ON d.device_id = e.device_id
         WHERE e.is_potential_download = 1 ORDER BY e.occurred_at DESC, e.id DESC LIMIT 5"
    )->fetchAll();
    $computers = $pdo->query("SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d WHERE d.status = 'active' ORDER BY d.last_heartbeat_at DESC LIMIT 5")->fetchAll();

    $steps = [
        [$devices["total"] > 0, "Add a computer", "Generate a token and run the agent installer on a PC.", "devices.php?view=tokens", "Add a computer"],
        [(int) $counts["all_events"] > 0, "See a download", "Download any file on that PC; it appears under File events.", "devices.php?view=events", "Open file events"],
        [(int) $counts["scans"] > 0, "Scan a file", "Click Scan next to a file event, or upload a file here.", "dashboard.php?view=scanner", "Scan a file"],
    ];
    $allDone = !in_array(false, array_column($steps, 0), true);

    mg_admin_page_start($admin, "home", "Dashboard", "Everything at a glance. Click a number to see the details.",
        '<a class="button" href="devices.php?view=tokens"><i class="fa-solid fa-plus" aria-hidden="true"></i>Add a computer</a>'
        . '<a class="button primary" href="dashboard.php?view=scanner"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Scan a file</a>');
    mg_admin_notice($notice);
    ?>
    <section class="stats" aria-label="Summary">
        <a class="stat ok" href="devices.php?view=computers"><span><i class="fa-solid fa-desktop" aria-hidden="true"></i>Computers online</span><strong><?= $devices["online"] ?> / <?= $devices["total"] ?></strong><small><?= $devices["offline"] ?> offline</small></a>
        <a class="stat" href="devices.php?view=events&amp;downloads=1"><span><i class="fa-solid fa-file-arrow-down" aria-hidden="true"></i>New files (24 h)</span><strong><?= (int) $counts["new_files"] ?></strong><small>Downloads detected on computers</small></a>
        <a class="stat warn" href="devices.php?view=scans"><span><i class="fa-solid fa-hourglass-half" aria-hidden="true"></i>Scans waiting</span><strong><?= (int) $counts["pending"] ?></strong><small>Waiting for a computer</small></a>
        <a class="stat" href="dashboard.php?view=history"><span><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i>Total scans</span><strong><?= (int) $counts["scans"] ?></strong><small>Uploads and computer scans</small></a>
        <a class="stat bad" href="dashboard.php?view=threats"><span><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>Threats</span><strong><?= (int) $counts["threats"] ?></strong><small>Medium, High or Critical</small></a>
    </section>

    <?php if (!$allDone): ?>
        <section class="panel">
            <div class="panel-head"><div><h2>Getting started</h2><p>Three steps to see MalwareGuard working.</p></div></div>
            <ol class="checklist">
                <?php foreach ($steps as $i => [$done, $title, $text, $url, $button]): ?>
                    <li class="<?= $done ? "done" : "" ?>">
                        <span class="step"><?= $done ? '<i class="fa-solid fa-check" aria-hidden="true"></i>' : $i + 1 ?></span>
                        <div><strong><?= mg_h($title) ?></strong><p><?= mg_h($text) ?></p>
                            <?php if (!$done): ?><a class="button small" href="<?= mg_h($url) ?>"><?= mg_h($button) ?></a><?php else: ?><small>Done</small><?php endif; ?>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ol>
        </section>
    <?php endif; ?>

    <div class="grid-2">
        <section class="panel">
            <div class="panel-head"><h2>Recent threats</h2><a href="dashboard.php?view=threats">View all</a></div>
            <?php if ($recentThreats): ?>
                <ul class="list">
                    <?php foreach ($recentThreats as $row): ?>
                        <li>
                            <div class="item-main">
                                <strong><a href="dashboard.php?view=threats&amp;scan=<?= (int) $row["id"] ?>#scan-detail"><?= mg_h($row["original_file_name"]) ?></a></strong>
                                <small><?= scan_source_label($row) ?> · <?= mg_h($row["scanned_at"]) ?></small>
                            </div>
                            <?= mg_risk_badge($row["threat_level"]) ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <?php mg_admin_empty("fa-circle-check", "No threats found", "Files rated Medium, High or Critical will be listed here."); ?>
            <?php endif; ?>
        </section>

        <section class="panel">
            <div class="panel-head"><h2>Recent downloads</h2><a href="devices.php?view=events&amp;downloads=1">View all</a></div>
            <?php if ($recentDownloads): ?>
                <ul class="list">
                    <?php foreach ($recentDownloads as $row): ?>
                        <li>
                            <div class="item-main">
                                <strong><?= mg_h($row["file_name"]) ?></strong>
                                <small><i class="fa-solid fa-desktop" aria-hidden="true"></i> <?= mg_h(($row["display_name"] ?: $row["hostname"]) ?: $row["device_id"]) ?> · <?= mg_h($row["occurred_at"]) ?></small>
                            </div>
                            <a class="button small" href="devices.php?view=events&amp;q=<?= urlencode($row["file_name"]) ?>">Open</a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <?php mg_admin_empty("fa-file-arrow-down", "No downloads yet", "When a monitored computer downloads a file, it shows up here."); ?>
            <?php endif; ?>
        </section>
    </div>

    <section class="panel" style="margin-top:24px;">
        <div class="panel-head"><h2>Computers</h2><a href="devices.php?view=computers">Manage computers</a></div>
        <?php if ($computers): ?>
            <ul class="list">
                <?php foreach ($computers as $device): ?>
                    <?php [$statusClass, $statusLabel, $statusDetail] = mg_device_status($device); ?>
                    <li>
                        <div class="item-main"><strong><?= mg_h(mg_device_label($device)) ?></strong><small><?= mg_h($statusDetail) ?></small></div>
                        <span class="badge <?= mg_h($statusClass) ?>"><?= mg_h($statusLabel) ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <?php mg_admin_empty("fa-desktop", "No computers yet", "Add a computer to start detecting downloads.", '<a class="button primary" href="devices.php?view=tokens"><i class="fa-solid fa-plus" aria-hidden="true"></i>Add a computer</a>'); ?>
        <?php endif; ?>
    </section>
    <?php
    mg_admin_page_end();
    exit;
}

if ($view === "scanner") {
    $uploadedScan = null;
    if ($uploadedScanId > 0) {
        $check = $pdo->prepare("SELECT id FROM scans WHERE id = ? AND user_id = ?");
        $check->execute([$uploadedScanId, $admin["id"]]);
        $uploadedScan = $check->fetchColumn() ?: null;
    }
    mg_admin_page_start($admin, "scanner", "File Scanner", "Upload a file (up to 50 MB) to check it. Only its SHA-256 hash is sent to VirusTotal; the file stays on this server.");
    ?>
    <section class="panel" id="file-scanner">
        <form class="dropzone" id="adminScanForm" action="../upload.php" method="post" enctype="multipart/form-data" data-custom="true">
            <div>
                <label for="admin-scan-file">File to check</label>
                <input id="admin-scan-file" name="scan_file" type="file" required>
            </div>
            <button id="adminScanButton" class="primary" type="submit"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i> <span id="adminScanButtonLabel">Scan file</span></button>
            <div class="progress" id="adminScanProgress" hidden>
                <p id="adminScanStatus" role="status" aria-live="polite">Uploading file...</p>
                <div class="progress-track" id="adminScanProgressTrack" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                    <span class="progress-fill" id="adminScanProgressFill"></span>
                </div>
            </div>
            <p class="form-error" id="adminScanError" role="alert" hidden></p>
        </form>
    </section>
    <?php
    if ($uploadedScan) {
        mg_render_scan_detail($pdo, (int) $uploadedScan, "dashboard.php?view=scanner");
    } elseif ($uploadedScanId > 0) {
        mg_admin_notice(["That scan result was not found.", true]);
    }
    $script = <<<'HTML'
    <script>
        const form = document.getElementById("adminScanForm");
        const input = document.getElementById("admin-scan-file");
        const button = document.getElementById("adminScanButton");
        const buttonLabel = document.getElementById("adminScanButtonLabel");
        const progress = document.getElementById("adminScanProgress");
        const statusText = document.getElementById("adminScanStatus");
        const track = document.getElementById("adminScanProgressTrack");
        const fill = document.getElementById("adminScanProgressFill");
        const errorBox = document.getElementById("adminScanError");
        let timer = null;

        function setProgress(percent, description) {
            fill.style.width = percent + "%";
            track.setAttribute("aria-valuenow", String(percent));
            track.setAttribute("aria-valuetext", description);
        }
        function showError(message) {
            clearInterval(timer);
            progress.hidden = true;
            button.disabled = false;
            buttonLabel.textContent = "Scan file";
            errorBox.textContent = message.trim().slice(0, 500) || "The scan could not be completed. Please try again.";
            errorBox.hidden = false;
        }
        form.addEventListener("submit", function (event) {
            event.preventDefault();
            if (!input.files.length) { input.reportValidity(); return; }
            clearInterval(timer);
            errorBox.hidden = true;
            progress.hidden = false;
            button.disabled = true;
            buttonLabel.textContent = "Scanning...";
            statusText.textContent = "Uploading file...";
            setProgress(0, "Upload has not started");

            const request = new XMLHttpRequest();
            request.open("POST", form.action);
            request.upload.addEventListener("progress", function (e) {
                if (!e.lengthComputable) return;
                const pct = Math.round((e.loaded / e.total) * 100);
                setProgress(Math.round(pct * 0.5), "Upload " + pct + "% complete");
                statusText.textContent = "Uploading file... " + pct + "%";
            });
            request.upload.addEventListener("load", function () {
                let estimate = 50;
                statusText.textContent = "Checking the file...";
                timer = setInterval(function () {
                    if (estimate >= 90) { clearInterval(timer); return; }
                    estimate += 1;
                    setProgress(estimate, "Analysis in progress");
                }, 400);
            });
            request.addEventListener("load", function () {
                clearInterval(timer);
                const url = new URL(request.responseURL || form.action, window.location.href);
                if (request.status >= 200 && request.status < 400 && url.pathname.endsWith("/admin/dashboard.php")) {
                    setProgress(100, "Scan complete");
                    statusText.textContent = "Done. Showing the result...";
                    window.location.assign(url.href);
                    return;
                }
                showError(request.responseText || "The scan could not be completed. Please try again.");
            });
            request.addEventListener("error", function () { showError("The upload was interrupted. Check your connection and try again."); });
            request.send(new FormData(form));
        });
    </script>
HTML;
    mg_admin_page_end($script);
    exit;
}

if (in_array($view, ["history", "threats", "quarantine"], true)) {
    $titles = [
        "history" => ["Scan History", "Every scan: files uploaded here and files scanned on monitored computers."],
        "threats" => ["Threats", "Scans rated Medium, High or Critical. Open one to see what was found and what to do."],
        "quarantine" => ["Quarantine", "Files uploaded through the scanner are stored here under a random name and can never be run by the server."],
    ];
    $query = is_string($_GET["q"] ?? null) ? mb_substr(trim($_GET["q"]), 0, 200) : "";
    $risk = is_string($_GET["risk"] ?? null) && in_array($_GET["risk"], ["safe", "low", "medium", "high", "critical", "unknown"], true) ? $_GET["risk"] : "";

    $where = [];
    $params = [];
    if ($view === "threats") {
        $where[] = $threatWhere;
    } elseif ($view === "quarantine") {
        $where[] = "s.file_path LIKE '%.quarantine'";
    }
    if ($query !== "") {
        $like = "%" . addcslashes($query, "\\%_") . "%";
        $where[] = "(s.original_file_name LIKE ? OR s.file_hash LIKE ?)";
        array_push($params, $like, $like);
    }
    if ($risk !== "") {
        $where[] = "s.threat_level = ?";
        $params[] = $risk;
    }
    $rows = scan_rows($pdo, implode(" AND ", $where), $params);

    mg_admin_page_start($admin, $view, $titles[$view][0], $titles[$view][1],
        '<a class="button primary" href="dashboard.php?view=scanner"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>Scan a file</a>');
    if ($detailId && !mg_render_scan_detail($pdo, $detailId, "dashboard.php?view=" . $view)) {
        mg_admin_notice(["That scan was not found.", true]);
    }
    ?>
    <section class="panel">
        <form method="get" action="dashboard.php" class="form-row toolbar">
            <input type="hidden" name="view" value="<?= mg_h($view) ?>">
            <div><label for="q">Search file name or hash</label><input id="q" name="q" type="search" value="<?= mg_h($query) ?>" placeholder="report.pdf"></div>
            <div><label for="risk">Risk</label>
                <select id="risk" name="risk">
                    <option value="">All levels</option>
                    <?php foreach (["critical", "high", "medium", "low", "safe", "unknown"] as $level): ?>
                        <option value="<?= $level ?>"<?= $risk === $level ? " selected" : "" ?>><?= ucfirst($level) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="actions"><button type="submit"><i class="fa-solid fa-filter" aria-hidden="true"></i>Filter</button><a class="button ghost" href="dashboard.php?view=<?= mg_h($view) ?>">Clear</a></div>
        </form>
        <?php
        $empty = [
            "history" => ["fa-clock-rotate-left", "No scans yet", "Scan a file here, or click Scan next to a file event from a computer."],
            "threats" => ["fa-circle-check", "No threats found", "Nothing has been rated Medium, High or Critical" . ($query !== "" || $risk !== "" ? " with these filters." : " yet.")],
            "quarantine" => ["fa-box-archive", "Quarantine is empty", "Files you upload with the File Scanner are kept here."],
        ][$view];
        render_scan_table($rows, $view, ...$empty);
        ?>
    </section>
    <?php
    mg_admin_page_end();
    exit;
}

// settings
mg_admin_page_start($admin, "settings", "Settings", "Your account.");
mg_admin_notice($notice);
?>
<div class="grid-2">
    <section class="panel">
        <div class="panel-head"><h2>Change password</h2></div>
        <form method="post" action="dashboard.php?view=settings" style="display:grid;gap:14px;">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="csrf_token" value="<?= mg_h($csrf) ?>">
            <div><label for="current-password">Current password</label><input id="current-password" name="current_password" type="password" autocomplete="current-password" required></div>
            <div><label for="new-password">New password (12+ characters)</label><input id="new-password" name="new_password" type="password" minlength="12" autocomplete="new-password" required></div>
            <div><label for="confirm-password">Confirm new password</label><input id="confirm-password" name="confirm_password" type="password" minlength="12" autocomplete="new-password" required></div>
            <div><button type="submit" class="primary">Update password</button></div>
        </form>
    </section>
    <section class="panel">
        <div class="panel-head"><h2>Account</h2></div>
        <div class="detail-grid">
            <div><span>Name</span><strong><?= mg_h($admin["name"]) ?></strong></div>
            <div><span>Role</span><strong><?= $admin["role"] === "super_admin" ? "Super admin" : "Admin" ?></strong></div>
            <div><span>Email</span><strong><?= mg_h($_SESSION["user_email"] ?? "") ?></strong></div>
        </div>
        <p class="hint" style="margin-top:14px;">Forgot your password? Run <code>php rotate_admin_password.php</code> in the project folder on the server.</p>
    </section>
</div>
<?php
mg_admin_page_end();
