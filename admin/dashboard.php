<?php
session_start();
require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "db.php";

if (
    ($_SESSION["logged_in"] ?? false) !== true ||
    !in_array($_SESSION["user_role"] ?? "", ["admin", "super_admin"], true) ||
    (($_SESSION["user_role"] ?? "") === "super_admin" && ($_SESSION["super_admin_verified"] ?? false) !== true)
) {
    header("Location: login.html");
    exit;
}

if (empty($_SESSION["admin_settings_csrf"])) {
    $_SESSION["admin_settings_csrf"] = bin2hex(random_bytes(32));
}

$settingsNotice = $_SESSION["admin_settings_notice"] ?? "";
$settingsNoticeIsError = $_SESSION["admin_settings_notice_error"] ?? false;
unset($_SESSION["admin_settings_notice"], $_SESSION["admin_settings_notice_error"]);
$scanResult = null;
$scanFindings = [];
$requestedScanId = filter_input(INPUT_GET, "scan_id", FILTER_VALIDATE_INT);

if ($requestedScanId !== false && $requestedScanId !== null && $requestedScanId > 0) {
    $resultStmt = $conn->prepare(
        "SELECT id, original_file_name, file_size, file_type, file_hash, detection_status, threat_level, security_score, analysis_result, scanned_at,
                vt_status, vt_malicious, vt_engines, detection_source, recommended_action
         FROM scans
         WHERE id = ? AND user_id = ?
         LIMIT 1"
    );
    $resultStmt->bind_param("ii", $requestedScanId, $_SESSION["user_id"]);
    $resultStmt->execute();
    $scanResult = $resultStmt->get_result()->fetch_assoc() ?: null;
    $resultStmt->close();

    if ($scanResult !== null) {
        $findingsStmt = $conn->prepare(
            "SELECT detection_name, severity, description, evidence
             FROM detection_results
             WHERE scan_id = ?
             ORDER BY id ASC"
        );
        $findingsStmt->bind_param("i", $requestedScanId);
        $findingsStmt->execute();
        $findingsResult = $findingsStmt->get_result();
        while ($finding = $findingsResult->fetch_assoc()) {
            $scanFindings[] = $finding;
        }
        $findingsStmt->close();
    }
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $readPostString = static function (string $key): string {
        $value = $_POST[$key] ?? "";
        return is_string($value) ? $value : "";
    };

    if ($readPostString("action") !== "change_password") {
        http_response_code(400);
        exit("Invalid settings request.");
    }

    $settingsNoticeIsError = false;
    if (!hash_equals($_SESSION["admin_settings_csrf"], $readPostString("csrf_token"))) {
        $settingsNotice = "The form expired. Reload the page and try again.";
        $settingsNoticeIsError = true;
    } else {
        $currentPassword = $readPostString("current_password");
        $newPassword = $readPostString("new_password");
        $confirmPassword = $readPostString("confirm_password");

        if (strlen($newPassword) < 12) {
            $settingsNotice = "New passwords must be at least 12 characters.";
            $settingsNoticeIsError = true;
        } elseif ($newPassword !== $confirmPassword) {
            $settingsNotice = "The new password confirmation does not match.";
            $settingsNoticeIsError = true;
        } else {
            $accountId = (int) $_SESSION["user_id"];
            $accountRole = $_SESSION["user_role"];
            $passwordStmt = $conn->prepare("SELECT password FROM users WHERE id = ? AND role = ? AND status = 'active' LIMIT 1");
            $passwordStmt->bind_param("is", $accountId, $accountRole);
            $passwordStmt->execute();
            $account = $passwordStmt->get_result()->fetch_assoc();
            $passwordStmt->close();

            if (!$account || !password_verify($currentPassword, $account["password"])) {
                $settingsNotice = "Current password is incorrect.";
                $settingsNoticeIsError = true;
            } else {
                $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $updatePassword = $conn->prepare("UPDATE users SET password = ? WHERE id = ? AND role = ?");
                $updatePassword->bind_param("sis", $passwordHash, $accountId, $accountRole);
                $updatePassword->execute();
                $updatePassword->close();
                session_regenerate_id(true);
                $settingsNotice = "Password updated successfully.";
            }
        }
    }

    $_SESSION["admin_settings_notice"] = $settingsNotice;
    $_SESSION["admin_settings_notice_error"] = $settingsNoticeIsError;
    $conn->close();
    header("Location: dashboard.php#settings");
    exit;
}

$stmt = $conn->prepare(
    "SELECT s.original_file_name, s.file_size, s.detection_status, s.threat_level, s.security_score, s.scanned_at, u.name, u.email
     FROM scans s JOIN users u ON u.id = s.user_id
     ORDER BY s.id DESC LIMIT 100"
);
$stmt->execute();
$scans = $stmt->get_result();
$stmt->close();

$threatStmt = $conn->prepare(
    "SELECT s.original_file_name, s.file_size, s.detection_status, s.threat_level, s.security_score, s.scanned_at, u.name, u.email
     FROM scans s JOIN users u ON u.id = s.user_id
     WHERE s.detection_status IN ('suspicious', 'malicious') OR s.threat_level IN ('high', 'critical')
     ORDER BY s.id DESC LIMIT 100"
);
$threatStmt->execute();
$threats = $threatStmt->get_result();
$threatStmt->close();

$quarantineStmt = $conn->prepare(
    "SELECT s.original_file_name, s.file_size, s.detection_status, s.threat_level, s.scanned_at, u.name, u.email
     FROM scans s JOIN users u ON u.id = s.user_id
     WHERE s.file_path LIKE '%.quarantine'
     ORDER BY s.id DESC LIMIT 100"
);
$quarantineStmt->execute();
$quarantinedFiles = $quarantineStmt->get_result();
$quarantineStmt->close();

$conn->close();

function e($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Activity | MalwareGuard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        :root {
            color-scheme: dark;
            --background: #0b0710;
            --surface: #160d19;
            --surface-raised: #1b1220;
            --border: #3a1c32;
            --pink: #ff4f9a;
            --text: #f8eaf2;
            --muted: #a8909d;
        }

        * { box-sizing: border-box; }

        body {
            min-height: 100vh;
            margin: 0;
            color: var(--text);
            font: 15px Arial, Helvetica, sans-serif;
            background: radial-gradient(circle at 75% 10%, rgba(255, 79, 154, 0.12), transparent 35%), var(--background);
        }

        header {
            position: sticky;
            top: 0;
            z-index: 1000;
            min-height: 75px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            padding: 14px max(20px, calc((100% - 1180px) / 2));
            background: rgba(11, 7, 16, 0.78);
            border-bottom: 1px solid var(--border);
            backdrop-filter: blur(15px);
        }

        h1 { margin: 0; font-size: 21px; }

        nav { display: flex; align-items: center; gap: 20px; }

        .workspace {
            display: grid;
            grid-template-columns: 220px minmax(0, 1fr);
            gap: 24px;
            max-width: 1500px;
            margin: 0 auto;
            padding: 28px 20px 48px;
        }

        .sidebar {
            position: sticky;
            top: 96px;
            z-index: 20;
            align-self: start;
            display: grid;
            gap: 6px;
            padding: 14px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: rgba(22, 13, 25, 0.92);
        }

        .sidebar-label {
            padding: 6px 10px 10px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
        }

        .sidebar a {
            display: flex;
            align-items: center;
            gap: 11px;
            min-height: 42px;
            padding: 0 11px;
            border: 1px solid transparent;
            border-radius: 7px;
            color: var(--muted);
            font-size: 14px;
            font-weight: 600;
        }

        .sidebar a:hover,
        .sidebar a[aria-current="page"] {
            border-color: rgba(255, 79, 154, 0.25);
            background: rgba(255, 79, 154, 0.1);
            color: var(--pink);
        }

        .sidebar a i { width: 18px; text-align: center; }

        .sidebar .sidebar-logout {
            margin-top: 8px;
            border-top: 1px solid var(--border);
            border-radius: 0;
        }

        a {
            color: var(--muted);
            text-decoration: none;
            transition: color 0.2s ease, background 0.2s ease;
        }

        a:hover { color: var(--pink); }

        nav a:last-child {
            padding: 10px 15px;
            border: 1px solid var(--pink);
            border-radius: 8px;
            color: var(--pink);
        }

        nav a:last-child:hover { background: var(--pink); color: #fff; }

        main { min-width: 0; padding: 10px 0 24px; }

        main > p {
            margin: 0 0 22px;
            color: var(--muted);
            line-height: 1.6;
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }

        .feature-card {
            padding: 18px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.9), rgba(17, 9, 20, 0.9));
        }

        .feature-card strong { display: block; margin-bottom: 7px; color: var(--text); font-size: 15px; }
        .feature-card span { color: var(--muted); font-size: 13px; line-height: 1.55; }

        .scanner-panel {
            margin-bottom: 24px;
            padding: 22px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.95), rgba(17, 9, 20, 0.95));
            scroll-margin-top: 100px;
        }

        .scanner-panel h2 { margin: 0 0 7px; font-size: 19px; }
        .scanner-panel p { margin: 0 0 18px; color: var(--muted); line-height: 1.5; }
        .scanner-form { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: 14px; }
        .scanner-form label { display: block; margin-bottom: 7px; color: var(--muted); font-size: 12px; font-weight: 600; }
        .scanner-form input[type="file"] { width: 100%; min-height: 44px; padding: 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface-raised); color: var(--text); }
        .scanner-form button { min-height: 44px; padding: 0 18px; border: 1px solid var(--pink); border-radius: 6px; background: var(--pink); color: #fff; font: inherit; font-weight: 700; cursor: pointer; }
        .scanner-form button:hover { filter: brightness(1.08); }
        .scanner-progress { grid-column: 1 / -1; }
        .scanner-progress p { margin: 0 0 8px; color: var(--muted); font-size: 13px; }
        .scanner-progress-track { height: 8px; overflow: hidden; border-radius: 8px; background: var(--surface-raised); }
        .scanner-progress-fill { display: block; width: 0; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--pink), #ff80b5); transition: width 160ms ease-out; }
        .scanner-error { grid-column: 1 / -1; margin: 0; color: #ff8794; line-height: 1.5; overflow-wrap: anywhere; }

        .scan-result-panel { margin: 18px 0 24px; padding: 20px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
        .scan-result-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 16px; }
        .scan-result-heading h2 { margin: 0; font-size: 18px; }
        .scan-result-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
        .scan-result-summary div { min-width: 0; padding: 12px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface-raised); }
        .scan-result-summary span { display: block; margin-bottom: 6px; color: var(--muted); font-size: 11px; text-transform: uppercase; }
        .scan-result-summary strong { overflow-wrap: anywhere; }
        .scan-result-description, .scan-finding { margin-top: 14px; padding: 14px; border: 1px solid var(--border); border-radius: 7px; background: var(--surface-raised); line-height: 1.55; overflow-wrap: anywhere; }
        .scan-findings { display: grid; gap: 10px; margin-top: 14px; }
        .scan-finding h3 { margin: 0 0 6px; font-size: 14px; }
        .scan-finding p { margin: 5px 0 0; color: var(--muted); }
        .scan-safe { color: #42f59e; }
        .scan-risk { color: #ff8794; }

        .table-wrap {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: rgba(22, 13, 25, 0.9);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
        }

        table { width: 100%; min-width: 900px; border-collapse: collapse; }

        th, td {
            padding: 14px 15px;
            border-bottom: 1px solid rgba(58, 28, 50, 0.75);
            text-align: left;
        }

        th {
            color: var(--pink);
            background: var(--surface-raised);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            white-space: nowrap;
        }

        td { color: var(--text); overflow-wrap: anywhere; }
        tbody tr:last-child td { border-bottom: 0; }
        tbody tr:hover { background: rgba(255, 79, 154, 0.045); }

        .settings-panel {
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: rgba(22, 13, 25, 0.9);
        }

        .settings-panel h2 { margin: 0 0 16px; font-size: 16px; }
        .settings-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; align-items: end; }
        .settings-form label { display: block; margin-bottom: 7px; color: var(--muted); font-size: 12px; font-weight: 600; }
        .settings-form input { width: 100%; height: 42px; padding: 0 11px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface-raised); color: var(--text); }
        .settings-form button { min-height: 42px; padding: 0 15px; border: 1px solid var(--pink); border-radius: 6px; background: transparent; color: var(--pink); font: inherit; font-weight: 700; cursor: pointer; }
        .settings-form button:hover { background: var(--pink); color: #fff; }
        .settings-notice { margin: 0 0 14px; color: #66e3b0; }
        .settings-notice.error { color: #ff8794; }
        main [id] { scroll-margin-top: 20px; }

        @media (max-width: 600px) {
            header { align-items: flex-start; flex-direction: column; padding: 16px 20px; }
            nav { width: 100%; justify-content: space-between; }
            .workspace { grid-template-columns: 1fr; gap: 16px; padding: 16px 14px 40px; }
            .sidebar { position: static; display: flex; flex-wrap: wrap; }
            .sidebar-label { flex-basis: 100%; }
            .sidebar a { flex: 1 1 140px; }
            .feature-grid { grid-template-columns: 1fr; }
            .scan-result-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .scanner-form { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <header>
        <h1>MalwareGuard scan activity</h1>
        <nav>
            <?php if (($_SESSION["user_role"] ?? "") === "super_admin" && ($_SESSION["super_admin_verified"] ?? false) === true): ?>
                <a href="../super_admin/dashboard.php">User database</a>
            <?php endif; ?>
            <a href="../logout.php">Sign out</a>
        </nav>
    </header>
    <div class="workspace">
        <aside class="sidebar" aria-label="Admin navigation">
            <div class="sidebar-label">WORKSPACE</div>
            <a href="#dashboard" aria-current="page"><i class="fa-solid fa-chart-line" aria-hidden="true"></i>Dashboard</a>
            <a href="#file-scanner"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i>File Scanner</a>
            <a href="#scan-history"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i>Scan History</a>
            <a href="#threats"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>Threats</a>
            <a href="#quarantine"><i class="fa-solid fa-box-archive" aria-hidden="true"></i>Quarantine</a>
            <a href="devices.php"><i class="fa-solid fa-desktop" aria-hidden="true"></i>Devices</a>
            <a href="#settings"><i class="fa-solid fa-gear" aria-hidden="true"></i>Settings</a>
            <a class="sidebar-logout" href="../logout.php"><i class="fa-solid fa-right-from-bracket" aria-hidden="true"></i>Sign out</a>
        </aside>

    <main id="dashboard">
        <p>Latest 100 file scans submitted to MalwareGuard. This view reports app activity only; it does not monitor activity outside the service.</p>
        <section class="feature-grid" aria-label="Detection capabilities">
            <div class="feature-card">
                <strong>Static file analysis</strong>
                <span>Scans uploaded files for suspicious indicators and assigns a risk score.</span>
            </div>
            <div class="feature-card">
                <strong>Optional threat intelligence</strong>
                <span>Hash reputation checks are available when a VirusTotal API key is configured.</span>
            </div>
            <div class="feature-card">
                <strong>Endpoint telemetry</strong>
                <span>Enrolled Windows agents report heartbeats and file activity in approved folders. <a href="devices.php">Manage devices</a>.</span>
            </div>
        </section>
        <section class="scanner-panel" id="file-scanner">
            <h2>File Scanner</h2>
            <p>Choose a file up to 50 MB to run a static security analysis.</p>
            <form class="scanner-form" id="adminScanForm" action="../upload.php" method="post" enctype="multipart/form-data">
                <div>
                    <label for="admin-scan-file">File to analyze</label>
                    <input id="admin-scan-file" name="scan_file" type="file" required>
                </div>
                <button id="adminScanButton" type="submit"><i class="fa-solid fa-shield-virus" aria-hidden="true"></i> <span id="adminScanButtonLabel">Analyze File</span></button>
                <div class="scanner-progress" id="adminScanProgress" hidden>
                    <p id="adminScanStatus" role="status" aria-live="polite">Uploading file...</p>
                    <div class="scanner-progress-track" id="adminScanProgressTrack" role="progressbar" aria-label="File scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                        <span class="scanner-progress-fill" id="adminScanProgressFill"></span>
                    </div>
                </div>
                <p class="scanner-error" id="adminScanError" role="alert" hidden></p>
            </form>
        </section>
        <?php if ($scanResult !== null): ?>
            <section class="scan-result-panel" id="scan-result" aria-live="polite">
                <div class="scan-result-heading">
                    <h2>File Analysis Result</h2>
                    <strong class="<?php echo in_array($scanResult["detection_status"], ["malicious", "suspicious"], true) ? "scan-risk" : "scan-safe"; ?>">
                        <?php echo e(strtoupper($scanResult["detection_status"])); ?>
                    </strong>
                </div>
                <div class="scan-result-summary">
                    <div><span>File</span><strong><?php echo e($scanResult["original_file_name"]); ?></strong></div>
                    <div><span>Threat level</span><strong><?php echo e(strtoupper($scanResult["threat_level"])); ?></strong></div>
                    <div><span>Security score</span><strong><?php echo e($scanResult["security_score"]); ?>/100</strong></div>
                    <div><span>Scanned</span><strong><?php echo e($scanResult["scanned_at"]); ?></strong></div>
                    <div><span>SHA-256</span><strong style="font-size:12px;"><?php echo e($scanResult["file_hash"]); ?></strong></div>
                    <div><span>Size</span><strong><?php echo number_format((int) $scanResult["file_size"]); ?> bytes</strong></div>
                    <div><span>Detection ratio</span><strong><?php echo ($scanResult["vt_status"] ?? "") === "found" ? e($scanResult["vt_malicious"] . "/" . $scanResult["vt_engines"]) . " VirusTotal" : "Not available (" . e(str_replace("_", " ", (string) ($scanResult["vt_status"] ?? "not checked"))) . ")"; ?></strong></div>
                    <div><span>Detection source</span><strong><?php echo e($scanResult["detection_source"] ?: "MalwareGuard static rules"); ?></strong></div>
                </div>
                <div class="scan-result-description"><strong>Recommended next action:</strong> <?php echo e($scanResult["recommended_action"] ?: "Review the findings below."); ?><br><small style="color:var(--muted);">The security score is 100 minus the points of matched rule indicators. It is not a probability that the file is safe.</small></div>
                <?php if (!empty($scanResult["analysis_result"])): ?>
                    <div class="scan-result-description"><?php echo nl2br(e($scanResult["analysis_result"])); ?></div>
                <?php endif; ?>
                <div class="scan-findings">
                    <h3>Detection Findings</h3>
                    <?php if ($scanFindings): ?>
                        <?php foreach ($scanFindings as $finding): ?>
                            <article class="scan-finding">
                                <h3><?php echo e($finding["detection_name"]); ?> · <?php echo e(strtoupper($finding["severity"])); ?></h3>
                                <p><?php echo e($finding["description"]); ?></p>
                                <?php if (!empty($finding["evidence"])): ?><p><?php echo e($finding["evidence"]); ?></p><?php endif; ?>
                            </article>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p>No configured suspicious indicators were detected.</p>
                    <?php endif; ?>
                </div>
            </section>
        <?php endif; ?>
        <div class="table-wrap" id="scan-history">
            <table>
                <thead><tr><th>User</th><th>Email</th><th>File</th><th>Size</th><th>Result</th><th>Threat</th><th>Score</th><th>Scanned</th></tr></thead>
                <tbody>
                    <?php while ($scan = $scans->fetch_assoc()): ?>
                    <tr>
                        <td><?php echo e($scan["name"]); ?></td>
                        <td><?php echo e($scan["email"]); ?></td>
                        <td><?php echo e($scan["original_file_name"]); ?></td>
                        <td><?php echo number_format((int) $scan["file_size"]); ?> bytes</td>
                        <td><?php echo e($scan["detection_status"]); ?></td>
                        <td><?php echo e($scan["threat_level"]); ?></td>
                        <td><?php echo e($scan["security_score"]); ?></td>
                        <td><?php echo e($scan["scanned_at"]); ?></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

        <section class="table-wrap" id="threats" style="margin-top:24px;">
            <table>
                <thead><tr><th>User</th><th>Email</th><th>File</th><th>Result</th><th>Threat</th><th>Score</th><th>Scanned</th></tr></thead>
                <tbody>
                    <?php if ($threats->num_rows > 0): ?>
                        <?php while ($threat = $threats->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo e($threat["name"]); ?></td>
                            <td><?php echo e($threat["email"]); ?></td>
                            <td><?php echo e($threat["original_file_name"]); ?></td>
                            <td><?php echo e($threat["detection_status"]); ?></td>
                            <td><?php echo e($threat["threat_level"]); ?></td>
                            <td><?php echo e($threat["security_score"]); ?></td>
                            <td><?php echo e($threat["scanned_at"]); ?></td>
                        </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr><td colspan="7">No suspicious or malicious scans were found.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>

        <section class="table-wrap" id="quarantine" style="margin-top:24px;">
            <table>
                <thead><tr><th>User</th><th>Email</th><th>File</th><th>Result</th><th>Threat</th><th>Size</th><th>Scanned</th></tr></thead>
                <tbody>
                    <?php if ($quarantinedFiles->num_rows > 0): ?>
                        <?php while ($file = $quarantinedFiles->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo e($file["name"]); ?></td>
                            <td><?php echo e($file["email"]); ?></td>
                            <td><?php echo e($file["original_file_name"]); ?></td>
                            <td><?php echo e($file["detection_status"]); ?></td>
                            <td><?php echo e($file["threat_level"]); ?></td>
                            <td><?php echo number_format((int) $file["file_size"]); ?> bytes</td>
                            <td><?php echo e($file["scanned_at"]); ?></td>
                        </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr><td colspan="7">No files are currently stored in quarantine.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </section>

        <section class="settings-panel" id="settings" style="margin-top:24px;">
            <h2>Account settings</h2>
            <?php if ($settingsNotice !== ""): ?>
                <p class="settings-notice<?php echo $settingsNoticeIsError ? " error" : ""; ?>" role="status"><?php echo e($settingsNotice); ?></p>
            <?php endif; ?>
            <form class="settings-form" method="post" action="dashboard.php#settings">
                <input type="hidden" name="action" value="change_password">
                <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION["admin_settings_csrf"]); ?>">
                <div>
                    <label for="current-password">Current password</label>
                    <input id="current-password" name="current_password" type="password" autocomplete="current-password" required>
                </div>
                <div>
                    <label for="new-password">New password (12+ characters)</label>
                    <input id="new-password" name="new_password" type="password" minlength="12" autocomplete="new-password" required>
                </div>
                <div>
                    <label for="confirm-password">Confirm new password</label>
                    <input id="confirm-password" name="confirm_password" type="password" minlength="12" autocomplete="new-password" required>
                </div>
                <button type="submit">Update Password</button>
            </form>
        </section>
    </main>
    </div>
    <script>
        const adminScanForm = document.getElementById("adminScanForm");
        const adminScanInput = document.getElementById("admin-scan-file");
        const adminScanButton = document.getElementById("adminScanButton");
        const adminScanButtonLabel = document.getElementById("adminScanButtonLabel");
        const adminScanProgress = document.getElementById("adminScanProgress");
        const adminScanStatus = document.getElementById("adminScanStatus");
        const adminScanProgressTrack = document.getElementById("adminScanProgressTrack");
        const adminScanProgressFill = document.getElementById("adminScanProgressFill");
        const adminScanError = document.getElementById("adminScanError");
        let adminScanEstimateTimer = null;

        function setAdminScanProgress(percent, description) {
            adminScanProgressFill.style.width = percent + "%";
            adminScanProgressTrack.setAttribute("aria-valuenow", String(percent));
            adminScanProgressTrack.setAttribute("aria-valuetext", description);
        }

        function showAdminScanError(message) {
            clearInterval(adminScanEstimateTimer);
            adminScanEstimateTimer = null;
            adminScanProgress.hidden = true;
            adminScanButton.disabled = false;
            adminScanButtonLabel.textContent = "Analyze File";
            adminScanError.textContent = message.trim().slice(0, 500) || "The scan could not be completed. Please try again.";
            adminScanError.hidden = false;
        }

        adminScanForm.addEventListener("submit", function (event) {
            event.preventDefault();
            if (!adminScanInput.files.length) {
                adminScanInput.reportValidity();
                return;
            }

            clearInterval(adminScanEstimateTimer);
            adminScanError.hidden = true;
            adminScanProgress.hidden = false;
            adminScanButton.disabled = true;
            adminScanButtonLabel.textContent = "Scanning...";
            adminScanStatus.textContent = "Uploading file...";
            setAdminScanProgress(0, "Upload has not started");

            const request = new XMLHttpRequest();
            request.open("POST", adminScanForm.action);
            request.upload.addEventListener("progress", function (progressEvent) {
                if (!progressEvent.lengthComputable) return;
                const uploadPercent = Math.round((progressEvent.loaded / progressEvent.total) * 100);
                setAdminScanProgress(Math.round(uploadPercent * 0.5), "Upload " + uploadPercent + "% complete");
                adminScanStatus.textContent = "Uploading file... " + uploadPercent + "%";
            });
            request.upload.addEventListener("load", function () {
                let estimatedPercent = 50;
                adminScanStatus.textContent = "Analyzing file...";
                setAdminScanProgress(estimatedPercent, "Analysis in progress; estimated " + estimatedPercent + "%");
                adminScanEstimateTimer = setInterval(function () {
                    if (estimatedPercent >= 90) {
                        clearInterval(adminScanEstimateTimer);
                        adminScanEstimateTimer = null;
                        return;
                    }
                    estimatedPercent += 1;
                    setAdminScanProgress(estimatedPercent, "Analysis in progress; estimated " + estimatedPercent + "%");
                }, 400);
            });
            request.addEventListener("load", function () {
                clearInterval(adminScanEstimateTimer);
                adminScanEstimateTimer = null;
                const responseUrl = new URL(request.responseURL || adminScanForm.action, window.location.href);

                if (request.status >= 200 && request.status < 400 && responseUrl.pathname.endsWith("/admin/dashboard.php")) {
                    setAdminScanProgress(100, "Scan complete");
                    adminScanStatus.textContent = "Scan complete. Showing result...";
                    window.location.assign(responseUrl.href);
                    return;
                }

                showAdminScanError(request.responseText || "The scan could not be completed. Please try again.");
            });
            request.addEventListener("error", function () {
                showAdminScanError("The upload was interrupted. Check your connection and try again.");
            });
            request.send(new FormData(adminScanForm));
        });
    </script>
</body>
</html>