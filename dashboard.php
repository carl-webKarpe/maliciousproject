<?php

session_start();

require_once "db.php";

if (
    !isset($_SESSION["logged_in"]) ||
    $_SESSION["logged_in"] !== true
) {
    header("Location: login.html?role=user");
    exit;
}

if (($userRole = $_SESSION["user_role"] ?? "") === "admin") {
    header("Location: admin/dashboard.php");
    exit;
}

if ($userRole === "super_admin" && ($_SESSION["super_admin_verified"] ?? false) === true) {
    header("Location: super_admin/dashboard.php");
    exit;
}

$userId = (int) $_SESSION["user_id"];


/*
|--------------------------------------------------------------------------
| Dashboard statistics
|--------------------------------------------------------------------------
*/

// Total scans
$stmt = $conn->prepare(
    "SELECT COUNT(*) AS total
     FROM scans
     WHERE user_id = ?"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$totalScans =
    (int) $stmt->get_result()->fetch_assoc()["total"];

$stmt->close();


// Safe files
$stmt = $conn->prepare(
    "SELECT COUNT(*) AS total
     FROM scans
     WHERE user_id = ?
     AND detection_status = 'safe'"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$safeFiles =
    (int) $stmt->get_result()->fetch_assoc()["total"];

$stmt->close();


// Threats
$stmt = $conn->prepare(
    "SELECT COUNT(*) AS total
     FROM scans
     WHERE user_id = ?
     AND detection_status IN ('suspicious', 'malicious')"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$threats =
    (int) $stmt->get_result()->fetch_assoc()["total"];

$stmt->close();


// Average security score
$stmt = $conn->prepare(
    "SELECT AVG(security_score) AS average_score
     FROM scans
     WHERE user_id = ?"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$scoreResult =
    $stmt->get_result()->fetch_assoc();

$averageScore =
    $scoreResult["average_score"] !== null
        ? round((float)$scoreResult["average_score"])
        : null;

$stmt->close();


// Recent scans
$stmt = $conn->prepare(
    "SELECT
        id,
        original_file_name,
        file_size,
        threat_level,
        detection_status,
        security_score,
        scanned_at
     FROM scans
     WHERE user_id = ?
     ORDER BY id DESC
     LIMIT 5"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$recentScans =
    $stmt->get_result();

$stmt->close();

$conn->close();


function e($value)
{
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES,
        "UTF-8"
    );
}


function bytes($size)
{
    if ($size <= 0) {
        return "0 Bytes";
    }

    $units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];

    $i = floor(
        log($size, 1024)
    );

    $i = min(
        $i,
        count($units) - 1
    );

    return round(
        $size / pow(1024, $i),
        2
    ) . " " . $units[$i];
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Dashboard | MalwareGuard
    </title>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >


    <style>
        :root {
            --pink: #ff4f9a;
            --pink-light: #ff80b5;
            --pink-dark: #d9367c;
            --pink-glow: rgba(255, 79, 154, 0.35);
            --background: #0b0710;
            --background-light: #130b16;
            --card: #160d19;
            --card-strong: #1b1220;
            --border: #3a1c32;
            --text: #f8eaf2;
            --muted: #a8909d;
            --safe: #42f59e;
            --warning: #ffc857;
            --danger: #ff6475;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at 75% 20%, rgba(255, 79, 154, 0.12), transparent 35%),
                var(--background);
        }

        body.light-mode {
            --background: #f6edf3;
            --background-light: #fff9fc;
            --card: #ffffff;
            --card-strong: #fff4fa;
            --border: #f0d6e7;
            --text: #1e1320;
            --muted: #625164;
            --safe: #0d9d62;
            --warning: #c47e00;
            --danger: #d9354e;
            --pink: #e53689;
            --pink-light: #ff7abc;
            --pink-dark: #b72267;
            --pink-glow: rgba(229, 54, 137, 0.18);
        }

        body.light-mode {
            background: linear-gradient(180deg, #fff9fb 0%, #f6edf3 100%);
            color: var(--text);
        }

        .theme-toggle {
            position: fixed;
            top: 90px;
            right: 22px;
            z-index: 2000;
            width: 48px;
            height: 48px;
            border: 1px solid var(--border);
            border-radius: 50%;
            background: rgba(16, 13, 22, 0.78);
            color: var(--text);
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.18);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: 0.3s ease;
        }

        body.light-mode .theme-toggle {
            background: rgba(255, 255, 255, 0.9);
        }

        .navbar {
            height: 75px;
            padding: 0 6%;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(11, 7, 16, 0.72);
            backdrop-filter: blur(15px);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 50;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 21px;
            font-weight: 700;
        }

        .logo-shield {
            width: 42px;
            height: 42px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            color: var(--pink);
            background: rgba(255, 79, 154, 0.08);
            border: 1px solid var(--pink);
            box-shadow: 0 0 15px var(--pink-glow);
        }

        .logo > span > span {
            color: var(--pink);
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 24px;
        }

        .nav-links a {
            color: var(--muted);
            text-decoration: none;
            font-size: 14px;
            transition: 0.3s;
        }

        .nav-links a:hover {
            color: var(--pink);
        }

        .logout {
            padding: 10px 15px;
            border: 1px solid var(--pink);
            border-radius: 9px;
            color: var(--pink) !important;
            box-shadow: 0 0 15px rgba(255, 79, 154, 0.12);
            transition: 0.3s;
        }

        .logout:hover {
            background: var(--pink);
            color: white !important;
        }

        .container {
            width: min(940px, calc(100% - 300px));
            margin: 0 20px 0 max(260px, calc((100% - 1200px) / 2 + 245px));
            padding: 55px 0 90px;
        }

        .heading {
            margin-bottom: 35px;
        }

        .label {
            color: var(--pink);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2px;
        }

        .heading h1 {
            margin: 10px 0;
            font-size: clamp(30px, 5vw, 48px);
        }

        .heading h1 span {
            color: var(--pink);
        }

        .heading p {
            color: var(--muted);
            margin: 0;
            line-height: 1.6;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 25px;
        }

        .stat-card {
            padding: 23px;
            display: flex;
            align-items: center;
            gap: 16px;
            border-radius: 16px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.97), rgba(17, 9, 20, 0.97));
            border: 1px solid var(--border);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
        }

        .stat-icon {
            width: 50px;
            height: 50px;
            flex-shrink: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 13px;
            color: var(--pink);
            background: rgba(255, 79, 154, 0.08);
            border: 1px solid rgba(255, 79, 154, 0.18);
        }

        .stat-icon.safe {
            color: var(--safe);
            background: rgba(66, 245, 158, 0.08);
            border-color: rgba(66, 245, 158, 0.2);
        }

        .stat-icon.danger {
            color: var(--danger);
            background: rgba(255, 100, 117, 0.08);
            border-color: rgba(255, 100, 117, 0.2);
        }

        .stat-card span {
            display: block;
            color: var(--muted);
            font-size: 10px;
            letter-spacing: 1.2px;
            font-weight: 700;
            margin-bottom: 6px;
        }

        .stat-card strong {
            font-size: 27px;
        }

        .scanner-cta {
            padding: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            border-radius: 18px;
            background: linear-gradient(120deg, rgba(255, 79, 154, 0.08), rgba(18, 12, 22, 0.9));
            border: 1px solid var(--border);
            margin-bottom: 25px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
        }

        .scanner-cta h2 {
            margin: 8px 0;
            font-size: 25px;
        }

        .scanner-cta p {
            margin: 0;
            color: var(--muted);
        }

        .primary-btn {
            display: inline-flex;
            align-items: center;
            gap: 9px;
            padding: 13px 20px;
            border-radius: 10px;
            color: white;
            background: linear-gradient(135deg, var(--pink), var(--pink-dark));
            text-decoration: none;
            font-size: 13px;
            font-weight: 800;
            white-space: nowrap;
            box-shadow: 0 0 25px var(--pink-glow);
        }

        .primary-btn:hover {
            transform: translateY(-1px);
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 25px;
        }

        .feature-card {
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 14px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.97), rgba(17, 9, 20, 0.97));
        }

        .feature-card i { color: var(--pink); font-size: 18px; margin-bottom: 12px; }
        .feature-card h3 { margin: 0 0 8px; font-size: 16px; }
        .feature-card p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.55; }

        .history-card {
            overflow: hidden;
            border-radius: 18px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.97), rgba(17, 9, 20, 0.97));
            border: 1px solid var(--border);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
        }

        .history-header {
            padding: 23px 25px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }

        .history-header h2 {
            margin: 6px 0 0;
            font-size: 21px;
        }

        .view-all {
            color: var(--pink);
            text-decoration: none;
            font-size: 13px;
        }

        .table-wrapper {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 700px;
        }

        th {
            text-align: left;
            color: var(--muted);
            font-size: 10px;
            letter-spacing: 1px;
            padding: 17px 25px;
        }

        td {
            padding: 17px 25px;
            border-top: 1px solid rgba(255,255,255,.045);
            color: #e6d9e4;
            font-size: 13px;
        }

        .file-name {
            color: var(--text);
            font-weight: 600;
        }

        .badge {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 20px;
            font-size: 9px;
            font-weight: 800;
            letter-spacing: .7px;
        }

        .badge.safe {
            color: var(--safe);
            background: rgba(66, 245, 158, 0.09);
        }

        .badge.suspicious,
        .badge.medium {
            color: var(--warning);
            background: rgba(255, 200, 87, 0.09);
        }

        .badge.malicious,
        .badge.high,
        .badge.critical {
            color: var(--danger);
            background: rgba(255, 100, 117, 0.09);
        }

        .score {
            color: var(--pink-light);
            font-weight: 700;
        }

        .result-link {
            color: var(--muted);
            text-decoration: none;
        }

        .result-link:hover {
            color: var(--pink);
        }

        .empty {
            padding: 60px 20px;
            text-align: center;
            color: var(--muted);
        }

        .empty i {
            font-size: 35px;
            color: var(--border);
            margin-bottom: 15px;
        }

        .empty h3 {
            margin: 0 0 7px;
            color: var(--text);
        }

        .empty p {
            margin: 0;
        }

        @media(max-width: 900px) {
            .container {
                width: 92%;
                margin: auto;
            }

            .feature-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media(max-width: 650px) {
            .nav-links a:not(.logout) {
                display: none;
            }

            .feature-grid,
            .stats {
                grid-template-columns: 1fr;
            }

            .scanner-cta {
                flex-direction: column;
                align-items: flex-start;
            }
        }
    </style>

        <link rel="stylesheet" href="assets/css/workspace-sidebar.css">

    </head>


<body>


<!-- NAVBAR -->

<nav class="navbar">

    <div class="logo">

        <div class="logo-shield">

            <i class="fa-solid fa-shield-halved"></i>

        </div>

        <span>
            Malware<span>Guard</span>
        </span>

    </div>


    <div class="nav-links">
        <a
            href="logout.php"
            class="logout"
        >

            <i class="fa-solid fa-right-from-bracket"></i>

            Logout

        </a>

    </div>

    <button class="theme-toggle" type="button" aria-label="Switch to light mode">
        <i class="fa-solid fa-moon"></i>
    </button>

</nav>

<?php
$workspaceSidebarCompact = true;
require __DIR__ . "/includes/workspace_sidebar.php";
?>

<main class="container">


    <!-- HEADING -->

    <div class="heading">

        <span class="label">
            SECURITY DASHBOARD
        </span>

        <h1>
            Welcome,
            <span><?= e($_SESSION["user_name"]) ?></span>
        </h1>

        <p>
            Monitor your file analysis activity and security results.
        </p>

    </div>


    <!-- STATS -->

    <div class="stats">


        <div class="stat-card">

            <div class="stat-icon">

                <i class="fa-solid fa-file-shield"></i>

            </div>

            <div>

                <span>
                    TOTAL SCANS
                </span>

                <strong>
                    <?= $totalScans ?>
                </strong>

            </div>

        </div>


        <div class="stat-card">

            <div class="stat-icon safe">

                <i class="fa-solid fa-circle-check"></i>

            </div>

            <div>

                <span>
                    SAFE FILES
                </span>

                <strong>
                    <?= $safeFiles ?>
                </strong>

            </div>

        </div>


        <div class="stat-card">

            <div class="stat-icon danger">

                <i class="fa-solid fa-virus-slash"></i>

            </div>

            <div>

                <span>
                    THREATS
                </span>

                <strong>
                    <?= $threats ?>
                </strong>

            </div>

        </div>


        <div class="stat-card">

            <div class="stat-icon">

                <i class="fa-solid fa-chart-line"></i>

            </div>

            <div>

                <span>
                    AVG SECURITY SCORE
                </span>

                <strong>

                    <?php if ($averageScore !== null): ?>

                        <?= $averageScore ?>%

                    <?php else: ?>

                        --

                    <?php endif; ?>

                </strong>

            </div>

        </div>

    </div>


    <div class="feature-grid" aria-label="Detection capabilities">
        <article class="feature-card">
            <i class="fa-solid fa-file-arrow-up"></i>
            <h3>File Scanning</h3>
            <p>Upload files for static checks of suspicious indicators and risk patterns.</p>
        </article>
        <article class="feature-card">
            <i class="fa-solid fa-shield-virus"></i>
            <h3>Threat Intelligence</h3>
            <p>Optional hash reputation can strengthen results when an API key is configured.</p>
        </article>
        <article class="feature-card">
            <i class="fa-solid fa-wand-sparkles"></i>
            <h3>AI Summary</h3>
            <p>Read a plain-language explanation of findings when AI service credentials are configured.</p>
        </article>
        <article class="feature-card">
            <i class="fa-solid fa-desktop"></i>
            <h3>Endpoint Activity</h3>
            <p>Windows activity requires a separately installed, consented local agent.</p>
        </article>
        <article class="feature-card">
            <i class="fa-solid fa-chart-pie"></i>
            <h3>Security Score</h3>
            <p>Review a percentage-based risk score with each scan result.</p>
        </article>
        <article class="feature-card">
            <i class="fa-solid fa-clock-rotate-left"></i>
            <h3>Scan History</h3>
            <p>Return to previous file checks and compare their results.</p>
        </article>
    </div>


    <!-- SCANNER CTA -->

    <div class="scanner-cta">

        <div>

            <span class="label">
                ENDPOINT DETECTION
            </span>

            <h2>
                Analyze a New File
            </h2>

            <p>
                Upload a file for static security analysis.
            </p>

        </div>


        <a
            href="scan.php"
            class="primary-btn"
        >

            <i class="fa-solid fa-shield-virus"></i>

            Start New Scan

        </a>

    </div>


    <!-- RECENT HISTORY -->

    <div class="history-card">


        <div class="history-header">

            <div>

                <span class="label">
                    SCAN HISTORY
                </span>

                <h2>
                    Recent Scans
                </h2>

            </div>


            <a
                href="history.php"
                class="view-all"
            >
                View All
                <i class="fa-solid fa-arrow-right"></i>
            </a>

        </div>


        <?php if ($recentScans->num_rows > 0): ?>


            <div class="table-wrapper">

                <table>

                    <thead>

                        <tr>

                            <th>
                                FILE
                            </th>

                            <th>
                                SIZE
                            </th>

                            <th>
                                STATUS
                            </th>

                            <th>
                                SCORE
                            </th>

                            <th>
                                DATE
                            </th>

                            <th>
                            </th>

                        </tr>

                    </thead>


                    <tbody>


                    <?php while (
                        $scan = $recentScans->fetch_assoc()
                    ): ?>


                        <tr>

                            <td>

                                <span class="file-name">

                                    <?= e(
                                        $scan["original_file_name"]
                                    ) ?>

                                </span>

                            </td>


                            <td>

                                <?= bytes(
                                    $scan["file_size"]
                                ) ?>

                            </td>


                            <td>

                                <span
                                    class="badge <?= e(
                                        $scan["detection_status"]
                                    ) ?>"
                                >

                                    <?= e(
                                        strtoupper(
                                            $scan["detection_status"]
                                        )
                                    ) ?>

                                </span>

                            </td>


                            <td>

                                <span class="score">

                                    <?= number_format(
                                        (float)$scan["security_score"],
                                        0
                                    ) ?>%

                                </span>

                            </td>


                            <td>

                                <?= e(
                                    $scan["scanned_at"]
                                ) ?>

                            </td>


                            <td>

                                <a
                                    href="results.php?id=<?= (int)$scan["id"] ?>"
                                    class="result-link"
                                >

                                    View

                                    <i class="fa-solid fa-arrow-right"></i>

                                </a>

                            </td>

                        </tr>


                    <?php endwhile; ?>


                    </tbody>

                </table>

            </div>


        <?php else: ?>


            <div class="empty">

                <i class="fa-solid fa-folder-open"></i>

                <h3>
                    No scans yet
                </h3>

                <p>
                    Start your first file analysis to see results here.
                </p>

            </div>


        <?php endif; ?>


    </div>


</main>

<script src="assets/js/script.js"></script>

</body>

</html>
