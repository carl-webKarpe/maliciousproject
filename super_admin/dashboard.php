<?php
session_start();
require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "db.php";
require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "includes" . DIRECTORY_SEPARATOR . "devices.php";

if (!isset($_SESSION["logged_in"]) || $_SESSION["logged_in"] !== true) {
    header("Location: ../login.html");
    exit;
}

if (($_SESSION["user_role"] ?? "") !== "super_admin" || ($_SESSION["super_admin_verified"] ?? false) !== true) {
    header("Location: ../dashboard.php");
    exit;
}

$adminManageCsrf = $_SESSION["admin_manage_csrf"] ??= bin2hex(random_bytes(32));

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $notice = "";
    $noticeType = "success";
    $readAdminPostString = static function (string $key): string {
        $value = $_POST[$key] ?? "";
        return is_string($value) ? $value : "";
    };

    try {
        if (!hash_equals($adminManageCsrf, $readAdminPostString("csrf_token"))) {
            throw new InvalidArgumentException("The form expired. Reload the page and try again.");
        }

        $action = $readAdminPostString("action");
        $accountId = filter_var($readAdminPostString("account_id"), FILTER_VALIDATE_INT);

        if ($action === "create") {
            $name = trim($readAdminPostString("name"));
            $email = strtolower(trim($readAdminPostString("email")));
            $password = $readAdminPostString("password");

            if ($name === "" || strlen($name) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                throw new InvalidArgumentException("Enter a valid name and email address.");
            }
            if (strlen($password) < 12) {
                throw new InvalidArgumentException("Admin passwords must be at least 12 characters.");
            }

            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $createAdmin = $conn->prepare(
                "INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, 'admin', 'active')"
            );
            $createAdmin->bind_param("sss", $name, $email, $passwordHash);
            $createAdmin->execute();
            $createAdmin->close();
            $notice = "Admin account created.";
        } elseif ($action === "edit" || $action === "reset_password" || $action === "delete") {
            if ($accountId === false || $accountId < 1) {
                throw new InvalidArgumentException("Select a valid admin account.");
            }

            if ($action === "edit") {
                $name = trim($readAdminPostString("name"));
                $email = strtolower(trim($readAdminPostString("email")));
                $status = $readAdminPostString("status");

                if ($name === "" || strlen($name) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                    throw new InvalidArgumentException("Enter a valid name and email address.");
                }
                if (!in_array($status, ["active", "inactive"], true)) {
                    throw new InvalidArgumentException("Choose a valid account status.");
                }

                $updateAdmin = $conn->prepare(
                    "UPDATE users SET name = ?, email = ?, status = ? WHERE id = ? AND role = 'admin'"
                );
                $updateAdmin->bind_param("sssi", $name, $email, $status, $accountId);
                $updateAdmin->execute();
                $updated = $updateAdmin->affected_rows;
                $updateAdmin->close();
                if ($updated === 0) {
                    $notice = "Admin details saved, or no changes were needed.";
                } else {
                    $notice = "Admin details updated.";
                }
            } elseif ($action === "reset_password") {
                $password = $readAdminPostString("password");
                if (strlen($password) < 12) {
                    throw new InvalidArgumentException("New passwords must be at least 12 characters.");
                }

                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $resetAdminPassword = $conn->prepare(
                    "UPDATE users SET password = ? WHERE id = ? AND role = 'admin'"
                );
                $resetAdminPassword->bind_param("si", $passwordHash, $accountId);
                $resetAdminPassword->execute();
                $updated = $resetAdminPassword->affected_rows;
                $resetAdminPassword->close();
                if ($updated === 0) {
                    throw new InvalidArgumentException("Admin account not found; password was not changed.");
                }
                $notice = "Admin password reset.";
            } else {
                $deleteAdmin = $conn->prepare("DELETE FROM users WHERE id = ? AND role = 'admin'");
                $deleteAdmin->bind_param("i", $accountId);
                $deleteAdmin->execute();
                $deleted = $deleteAdmin->affected_rows;
                $deleteAdmin->close();
                if ($deleted === 0) {
                    throw new InvalidArgumentException("Admin account not found; nothing was deleted.");
                }
                $notice = "Admin account deleted.";
            }
        } else {
            throw new InvalidArgumentException("Unknown admin account action.");
        }
    } catch (InvalidArgumentException $e) {
        $notice = $e->getMessage();
        $noticeType = "error";
    } catch (mysqli_sql_exception $e) {
        error_log("Super-admin account management failed: " . $e->getMessage());
        $notice = (int) $e->getCode() === 1062
            ? "That email address is already in use."
            : "The admin account change failed. Check the server log for details.";
        $noticeType = "error";
    }

    $_SESSION["admin_manage_notice"] = $notice;
    $_SESSION["admin_manage_notice_type"] = $noticeType;
    $conn->close();
    header("Location: dashboard.php#admin-management");
    exit;
}

$adminManageNotice = $_SESSION["admin_manage_notice"] ?? "";
$adminManageNoticeType = $_SESSION["admin_manage_notice_type"] ?? "success";
unset($_SESSION["admin_manage_notice"], $_SESSION["admin_manage_notice_type"]);

$stmt = $conn->prepare("SELECT id, name, email, role, status, last_login FROM users ORDER BY id ASC");
$stmt->execute();
$users = $stmt->get_result();
$stmt->close();

// Online status comes from recent authenticated heartbeats (includes/devices.php).
$endpointPdo = mg_pdo();
$endpointDevices = $endpointPdo->query(
    "SELECT " . MG_DEVICE_COLUMNS . " FROM endpoint_devices d
     ORDER BY d.last_heartbeat_at IS NULL, d.last_heartbeat_at DESC, d.id DESC LIMIT 10"
)->fetchAll();
$endpointSummary = mg_device_summary($endpointPdo);

$endpointAlertsStmt = $conn->prepare(
    "SELECT a.device_id, d.hostname, a.alert_type, a.severity, a.message, a.status, a.created_at
     FROM endpoint_alerts a
     LEFT JOIN endpoint_devices d ON d.device_id = a.device_id
     ORDER BY CASE WHEN a.status = 'open' THEN 0 ELSE 1 END, a.created_at DESC
     LIMIT 25"
);
$endpointAlertsStmt->execute();
$endpointAlerts = $endpointAlertsStmt->get_result();
$endpointAlertsStmt->close();

$scanStmt = $conn->prepare(
    "SELECT s.original_file_name, s.file_size, s.detection_status, s.threat_level, s.security_score, s.scanned_at, u.name, u.email
     FROM scans s JOIN users u ON u.id = s.user_id
     ORDER BY s.id DESC LIMIT 100"
);
$scanStmt->execute();
$scanActivity = $scanStmt->get_result();
$scanStmt->close();

$securityLogsStmt = $conn->prepare(
    "SELECT l.email, u.role, l.status, l.ip_address, l.user_agent, l.created_at
     FROM login_activity l
     LEFT JOIN users u ON u.id = l.user_id
     ORDER BY l.id DESC
     LIMIT 100"
);
$securityLogsStmt->execute();
$securityLogs = $securityLogsStmt->get_result();
$securityLogsStmt->close();

$managedAdminsStmt = $conn->prepare(
    "SELECT id, name, email, status, last_login FROM users WHERE role = 'admin' ORDER BY name, email"
);
$managedAdminsStmt->execute();
$managedAdmins = $managedAdminsStmt->get_result();
$managedAdminsStmt->close();

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin Dashboard | MalwareGuard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        :root {
            --header-height: 80px;
            --pink: #ff4f9a;
            --pink-light: #ff80b5;
            --pink-dark: #d9367c;
            --bg: #090b14;
            --panel: #121827;
            --panel-2: #1a1f2d;
            --border: #2c3140;
            --text: #f6edf3;
            --muted: #b8afbd;
            --green: #2dd4bf;
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: "Segoe UI", Arial, sans-serif;
            background: linear-gradient(135deg, #090b14, #0f1221);
            color: var(--text);
        }

        body.light-mode {
            --bg: #f9f1f6;
            --panel: #ffffff;
            --panel-2: #fff4fa;
            --border: #f0d9e9;
            --text: #1e1320;
            --muted: #625164;
            --green: #0d9d62;
            --pink-light: #d9367c;
            background: linear-gradient(135deg, #fff9fb, #f8edf4);
            color: var(--text);
        }

        .theme-toggle {
            width: 46px;
            height: 46px;
            border-radius: 50%;
            border: 1px solid var(--border);
            background: rgba(255, 255, 255, 0.08);
            color: var(--text);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.12);
            flex: 0 0 auto;
        }

        .topbar {
            position: sticky;
            top: 0;
            z-index: 1000;
            display: flex;
            align-items: center;
            justify-content: space-between;
            min-height: var(--header-height);
            padding: 18px 40px;
            border-bottom: 1px solid var(--border);
            background: rgba(12, 16, 28, 0.97);
            backdrop-filter: blur(14px);
        }

        .brand {
            font-size: 28px;
            font-weight: 800;
        }

        .brand span { color: var(--pink); }

        .nav-actions {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .welcome {
            color: var(--muted);
            font-size: 14px;
        }

        .dashboard-layout {
            display: grid;
            grid-template-columns: 230px minmax(0, 1fr);
            gap: 24px;
            max-width: 1520px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .admin-sidebar {
            position: sticky;
            top: calc(var(--header-height) + 16px);
            align-self: start;
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 32px;
            padding: 14px;
            border: 1px solid var(--border);
            border-radius: 14px;
            background: linear-gradient(145deg, rgba(18, 24, 39, 0.98), rgba(14, 18, 30, 0.98));
        }

        .sidebar-label {
            padding: 6px 10px 10px;
            color: var(--muted);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
        }

        .admin-sidebar a {
            display: flex;
            align-items: center;
            gap: 11px;
            min-height: 42px;
            padding: 0 11px;
            border: 1px solid transparent;
            border-radius: 8px;
            color: var(--muted);
            font-size: 14px;
            font-weight: 600;
            text-decoration: none;
        }

        .admin-sidebar a:hover,
        .admin-sidebar a[aria-current="page"] {
            border-color: rgba(255, 79, 154, 0.2);
            background: rgba(255, 79, 154, 0.12);
            color: var(--pink-light);
        }

        .admin-sidebar a i {
            width: 18px;
            text-align: center;
        }

        .admin-sidebar .sidebar-logout {
            margin-top: 8px;
            border-top: 1px solid var(--border);
            border-radius: 0;
            color: var(--pink-light);
        }

        .container {
            min-width: 0;
            margin: 32px 0;
            padding: 0 0 40px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(145deg, rgba(18, 24, 39, 0.95), rgba(14, 18, 30, 0.95));
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 22px;
        }

        .stat-label {
            color: var(--muted);
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: .08em;
        }

        .stat-value {
            margin-top: 10px;
            font-size: 34px;
            font-weight: 800;
        }

        .panel-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 22px;
            margin-bottom: 28px;
        }

        .panel {
            background: linear-gradient(145deg, rgba(18, 24, 39, 0.95), rgba(14, 18, 30, 0.95));
            border: 1px solid var(--border);
            border-radius: 18px;
            overflow: hidden;
        }

        .panel-head {
            padding: 18px 18px 14px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-title {
            font-size: 12px;
            letter-spacing: .08em;
            text-transform: uppercase;
            color: var(--pink-light);
            font-weight: 700;
        }

        .panel-body {
            padding: 18px;
        }

        .admin-management-content {
            padding: 18px;
        }

        .admin-create-form,
        .admin-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            align-items: end;
            gap: 12px;
        }

        .admin-create-form {
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }

        .admin-row-list {
            display: grid;
            gap: 14px;
            padding-top: 18px;
        }

        .admin-row {
            padding: 14px;
            border: 1px solid var(--border);
            border-radius: 8px;
        }

        .admin-field label {
            display: block;
            margin-bottom: 7px;
            color: var(--muted);
            font-size: 12px;
            font-weight: 600;
        }

        .admin-field input,
        .admin-field select {
            width: 100%;
            min-width: 0;
            height: 40px;
            padding: 0 10px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--panel-2);
            color: var(--text);
            font: inherit;
        }

        .admin-actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            grid-column: 1 / -1;
        }

        .admin-action {
            min-height: 38px;
            padding: 0 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--panel-2);
            color: var(--text);
            font: inherit;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
        }

        .admin-action:hover {
            border-color: var(--pink);
            color: var(--pink-light);
        }

        .admin-action.danger {
            color: #ff8794;
        }

        .admin-manage-notice {
            margin-bottom: 16px;
            padding: 12px 14px;
            border: 1px solid rgba(45, 212, 191, 0.25);
            border-radius: 6px;
            color: var(--green);
        }

        .admin-manage-notice.error {
            border-color: rgba(255, 100, 117, 0.35);
            color: #ff8794;
        }

        .table-wrap {
            background: linear-gradient(145deg, rgba(18, 24, 39, 0.95), rgba(14, 18, 30, 0.95));
            border: 1px solid var(--border);
            border-radius: 18px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 16px 18px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: rgba(255, 79, 154, 0.05);
            color: var(--pink-light);
            font-size: 12px;
            letter-spacing: .08em;
            text-transform: uppercase;
        }

        td {
            color: var(--text);
            font-size: 14px;
        }

        .badge {
            display: inline-block;
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 11px;
            font-weight: 700;
            background: rgba(45, 212, 191, 0.12);
            color: var(--green);
            border: 1px solid rgba(45, 212, 191, 0.25);
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 999px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
        }

        .severity-badge.warning {
            color: #ffc857;
            background: rgba(255, 200, 87, 0.12);
        }

        .severity-badge.danger {
            color: #ff6475;
            background: rgba(255, 100, 117, 0.12);
        }

        .alert-table-wrap { margin-bottom: 28px; overflow-x: auto; }
        .alert-table-wrap table { min-width: 760px; }
        .alert-message { max-width: 520px; overflow-wrap: anywhere; }
        .activity-table-wrap { overflow-x: auto; }
        .activity-table { min-width: 900px; }
        .container [id] { scroll-margin-top: calc(var(--header-height) + 16px); }

        @media (max-width: 700px) {
            :root { --header-height: 130px; }

            .topbar {
                align-items: stretch;
                flex-direction: column;
                padding: 18px 20px;
                gap: 12px;
            }

            .nav-actions {
                justify-content: space-between;
            }

            .brand {
                font-size: 23px;
            }

            .dashboard-layout {
                display: block;
            }

            .admin-sidebar {
                top: calc(var(--header-height) + 8px);
                flex-direction: row;
                flex-wrap: wrap;
                margin-top: 16px;
            }

            .sidebar-label {
                flex-basis: 100%;
            }

            .admin-sidebar a {
                flex: 1 1 145px;
            }

            .container {
                margin: 20px 0;
                padding: 0 0 30px;
            }

            .stats,
            .panel-grid {
                grid-template-columns: 1fr;
            }

            .table-wrap {
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="brand">Malware<span>Guard</span></div>
        <div class="nav-actions">
            <span class="welcome">Welcome, <?php echo htmlspecialchars($_SESSION['user_name'] ?? 'Admin'); ?></span>
            <button class="theme-toggle" type="button" aria-label="Switch to light mode" title="Switch theme">
                <i class="fa-solid fa-moon"></i>
            </button>
        </div>
    </header>

    <div class="dashboard-layout">
        <aside class="admin-sidebar" aria-label="Super admin navigation">
            <div class="sidebar-label">SUPER ADMIN</div>
            <a href="#dashboard" aria-current="page"><i class="fa-solid fa-chart-line" aria-hidden="true"></i>Dashboard</a>
            <a href="#scan-activity"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i>Scan Activity</a>
            <a href="#security-logs"><i class="fa-solid fa-clipboard-list" aria-hidden="true"></i>Security Logs</a>
            <a href="#endpoint-monitoring"><i class="fa-solid fa-desktop" aria-hidden="true"></i>Security Agents</a>
            <a href="../admin/devices.php"><i class="fa-solid fa-laptop-code" aria-hidden="true"></i>Device Management</a>
            <a href="#recent-endpoint-detections"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>Recent Detections</a>
            <a href="#user-accounts"><i class="fa-solid fa-users" aria-hidden="true"></i>User Accounts</a>
            <a href="#admin-management"><i class="fa-solid fa-user-gear" aria-hidden="true"></i>Manage Admins</a>
            <a class="sidebar-logout" href="../logout.php"><i class="fa-solid fa-right-from-bracket" aria-hidden="true"></i>Logout</a>
        </aside>

    <main class="container" id="dashboard">
        <section class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Users</div>
                <div class="stat-value"><?php echo $users->num_rows; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Active Users</div>
                <div class="stat-value"><?php
                    $activeCount = 0;
                    while ($user = $users->fetch_assoc()) {
                        if ($user['status'] === 'active') $activeCount++;
                    }
                    echo $activeCount;
                ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Admin Role</div>
                <div class="stat-value"><?php
                    $users->data_seek(0);
                    $adminCount = 0;
                    while ($u = $users->fetch_assoc()) { if ($u['role'] === 'admin') $adminCount++; }
                    echo $adminCount;
                ?></div>
            </div>
        </section>

        <section class="panel-grid">
            <div class="panel" id="endpoint-monitoring">
                <div class="panel-head">
                    <div class="panel-title">Endpoint devices</div>
                    <span class="badge"><?php echo (int) $endpointSummary['total']; ?> registered</span>
                </div>
                <div class="panel-body">
                    <?php if ($endpointDevices): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>Device</th>
                                    <th>Status</th>
                                    <th>Last heartbeat</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($endpointDevices as $device): ?>
                                    <?php [, $deviceStatusLabel] = mg_device_status($device); ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars(mg_device_label($device)); ?></td>
                                        <td><?php echo htmlspecialchars($deviceStatusLabel); ?></td>
                                        <td><?php echo htmlspecialchars($device['last_heartbeat_at'] ?: 'Never'); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p style="margin:0;color:var(--muted);">No endpoint agents have registered yet. <a href="../admin/devices.php#tokens">Generate an enrollment token</a> to add a computer.</p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="panel" id="endpoint-health">
                <div class="panel-head">
                    <div class="panel-title"></div>
                    <span class="badge"><?php echo (int) $endpointSummary['online']; ?> online</span>
                </div>
                <div class="panel-body">
                    <p style="margin-top:0;color:var(--muted);line-height:1.7;">
                        Windows endpoint telemetry is stored only after a consented agent registers and sends heartbeat data. This is a separate channel from the browser-based file scan flow and requires a local agent on the host device.
                    </p>
                    <p style="margin:0;"><a href="../admin/devices.php"><i class="fa-solid fa-desktop" aria-hidden="true"></i> Manage devices, tokens, file events and agent scans</a></p>
                </div>
            </div>
        </section>

        <section class="panel" id="recent-endpoint-detections" aria-label="Recent endpoint detections" style="margin-bottom:28px;">
            <div class="panel-head">
                <div class="panel-title">Recent endpoint detections</div>
                <span class="badge"><?php echo $endpointAlerts->num_rows; ?> shown</span>
            </div>
            <?php if ($endpointAlerts->num_rows > 0): ?>
                <div class="alert-table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>Severity</th>
                                <th>Detection</th>
                                <th>Details</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($alert = $endpointAlerts->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($alert['hostname'] ?: $alert['device_id'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><span class="severity-badge <?php echo in_array($alert['severity'], ['high', 'critical'], true) ? 'danger' : 'warning'; ?>"><?php echo htmlspecialchars($alert['severity'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                                    <td><?php echo htmlspecialchars($alert['alert_type'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td class="alert-message"><?php echo htmlspecialchars($alert['message'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($alert['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div class="panel-body">
                    <p style="margin:0;color:var(--muted);">No endpoint detections have been reported. Connect a Windows agent to start monitoring.</p>
                </div>
            <?php endif; ?>
        </section>

        <section class="table-wrap" id="security-logs" aria-label="Security logs" style="margin-bottom:28px;">
            <div class="panel-head">
                <div class="panel-title">Security logs</div>
                <span class="badge"><?php echo $securityLogs->num_rows; ?> shown</span>
            </div>
            <div class="activity-table-wrap">
                <table class="activity-table">
                    <thead>
                        <tr>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Event</th>
                            <th>IP Address</th>
                            <th>Browser / Agent</th>
                            <th>Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($securityLogs->num_rows > 0): ?>
                            <?php while ($log = $securityLogs->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($log['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($log['role'] ?? 'unknown', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($log['status'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($log['ip_address'] ?: 'Not recorded', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($log['user_agent'] ?: 'Not recorded', ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($log['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr><td colspan="6">No security logs have been recorded yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <section class="table-wrap" id="scan-activity" aria-label="Recent scan activity" style="margin-bottom:28px;">
            <div class="panel-head">
                <div class="panel-title">Recent scan activity</div>
                <span class="badge"><?php echo $scanActivity->num_rows; ?> shown</span>
            </div>
            <div class="activity-table-wrap">
                <table class="activity-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>File</th>
                            <th>Size</th>
                            <th>Result</th>
                            <th>Threat</th>
                            <th>Score</th>
                            <th>Scanned</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($scanActivity->num_rows > 0): ?>
                            <?php while ($scan = $scanActivity->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($scan['name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($scan['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($scan['original_file_name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo number_format((int) $scan['file_size']); ?> bytes</td>
                                    <td><?php echo htmlspecialchars($scan['detection_status'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($scan['threat_level'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars((string) $scan['security_score'], ENT_QUOTES, 'UTF-8'); ?></td>
                                    <td><?php echo htmlspecialchars($scan['scanned_at'], ENT_QUOTES, 'UTF-8'); ?></td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr><td colspan="8">No scan activity has been recorded yet.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <div class="table-wrap" id="user-accounts">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $users->data_seek(0);
                    while ($user = $users->fetch_assoc()):
                    ?>
                    <tr>
                        <td><?php echo (int) $user['id']; ?></td>
                        <td><?php echo htmlspecialchars($user['name']); ?></td>
                        <td><?php echo htmlspecialchars($user['email']); ?></td>
                        <td><?php echo htmlspecialchars($user['role']); ?></td>
                        <td><span class="badge"><?php echo htmlspecialchars($user['status']); ?></span></td>
                        <td><?php echo htmlspecialchars($user['last_login'] ?? 'Never'); ?></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

        <section class="table-wrap" id="admin-management" style="margin-top:28px;">
            <div class="panel-head">
                <div class="panel-title">Manage admin accounts</div>
                <span class="badge"><?php echo $managedAdmins->num_rows; ?> admins</span>
            </div>
            <div class="admin-management-content">
                <?php if ($adminManageNotice !== ""): ?>
                    <div class="admin-manage-notice<?php echo $adminManageNoticeType === "error" ? " error" : ""; ?>" role="status">
                        <?php echo htmlspecialchars($adminManageNotice, ENT_QUOTES, "UTF-8"); ?>
                    </div>
                <?php endif; ?>

                <form class="admin-create-form" method="post" action="dashboard.php#admin-management">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($adminManageCsrf, ENT_QUOTES, "UTF-8"); ?>">
                    <input type="hidden" name="action" value="create">
                    <div class="admin-field">
                        <label for="new-admin-name">Name</label>
                        <input id="new-admin-name" name="name" maxlength="100" autocomplete="name" required>
                    </div>
                    <div class="admin-field">
                        <label for="new-admin-email">Email</label>
                        <input id="new-admin-email" name="email" type="email" maxlength="255" autocomplete="email" required>
                    </div>
                    <div class="admin-field">
                        <label for="new-admin-password">Initial password (12+ characters)</label>
                        <input id="new-admin-password" name="password" type="password" minlength="12" autocomplete="new-password" required>
                    </div>
                    <button class="admin-action" type="submit">Create Admin</button>
                </form>

                <div class="admin-row-list" id="managed-admin-list">
                    <?php if ($managedAdmins->num_rows > 0): ?>
                        <?php while ($admin = $managedAdmins->fetch_assoc()): ?>
                            <form class="admin-row" method="post" action="dashboard.php#admin-management">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($adminManageCsrf, ENT_QUOTES, "UTF-8"); ?>">
                                <input type="hidden" name="account_id" value="<?php echo (int) $admin["id"]; ?>">
                                <div class="admin-field">
                                    <label for="admin-name-<?php echo (int) $admin["id"]; ?>">Name</label>
                                    <input id="admin-name-<?php echo (int) $admin["id"]; ?>" name="name" value="<?php echo htmlspecialchars($admin["name"], ENT_QUOTES, "UTF-8"); ?>" maxlength="100" required>
                                </div>
                                <div class="admin-field">
                                    <label for="admin-email-<?php echo (int) $admin["id"]; ?>">Email</label>
                                    <input id="admin-email-<?php echo (int) $admin["id"]; ?>" name="email" type="email" value="<?php echo htmlspecialchars($admin["email"], ENT_QUOTES, "UTF-8"); ?>" maxlength="255" required>
                                </div>
                                <div class="admin-field">
                                    <label for="admin-status-<?php echo (int) $admin["id"]; ?>">Status</label>
                                    <select id="admin-status-<?php echo (int) $admin["id"]; ?>" name="status">
                                        <option value="active"<?php echo $admin["status"] === "active" ? " selected" : ""; ?>>Active</option>
                                        <option value="inactive"<?php echo $admin["status"] === "inactive" ? " selected" : ""; ?>>Inactive</option>
                                    </select>
                                </div>
                                <div class="admin-field">
                                    <label for="admin-password-<?php echo (int) $admin["id"]; ?>">New password (12+ characters)</label>
                                    <input id="admin-password-<?php echo (int) $admin["id"]; ?>" name="password" type="password" minlength="12" autocomplete="new-password" placeholder="Required only to reset">
                                </div>
                                <div class="admin-actions">
                                    <button class="admin-action" type="submit" name="action" value="edit">Save Changes</button>
                                    <button class="admin-action" type="submit" name="action" value="reset_password">Reset Password</button>
                                    <button class="admin-action danger" type="submit" name="action" value="delete" formnovalidate onclick="return confirm('Delete this admin account?');">Delete</button>
                                </div>
                            </form>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <p style="margin:0;color:var(--muted);">No admin accounts exist yet.</p>
                    <?php endif; ?>
                </div>
            </div>
        </section>
    </main>
    </div>
    <script src="../assets/js/script.js"></script>
</body>
</html>
