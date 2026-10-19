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


$userId = (int)$_SESSION["user_id"];


$stmt = $conn->prepare(
    "SELECT
        id,
        original_file_name,
        file_size,
        file_type,
        file_extension,
        threat_level,
        detection_status,
        security_score,
        detection_count,
        scanned_at
     FROM scans
     WHERE user_id = ?
     ORDER BY id DESC"
);


$stmt->bind_param(
    "i",
    $userId
);

$stmt->execute();

$scans = $stmt->get_result();


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
        Scan History | MalwareGuard
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
            --panel: rgba(255, 255, 255, 0.03);
            --soft-panel: rgba(255, 255, 255, 0.02);
            --shadow: rgba(0, 0, 0, 0.3);
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
            --pink: #e53689;
            --pink-light: #ff7abc;
            --pink-dark: #b72267;
            --pink-glow: rgba(229, 54, 137, 0.18);
            --background: #f7f0f5;
            --background-light: #fff6fb;
            --card: #ffffff;
            --card-strong: #fff4fa;
            --border: #f0d6e7;
            --text: #1e1320;
            --muted: #625164;
            --panel: rgba(255, 255, 255, 0.9);
            --soft-panel: rgba(255, 255, 255, 0.7);
            --shadow: rgba(214, 142, 176, 0.18);
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
            background: rgba(255, 255, 255, 0.8);
        }

        .navbar {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 75px;
            padding: 0 6%;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(11, 7, 16, 0.55);
            backdrop-filter: blur(15px);
            border-bottom: 1px solid transparent;
            z-index: 1000;
            transition: 0.3s;
        }

        body.light-mode .navbar {
            background: rgba(255, 255, 255, 0.86);
            border-bottom-color: var(--border);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 22px;
            font-weight: 700;
        }

        .logo-shield {
            width: 38px;
            height: 38px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 10px;
            color: var(--pink);
            border: 1px solid var(--pink);
            box-shadow: 0 0 15px var(--pink-glow);
            background: rgba(255, 79, 154, 0.06);
        }

        .logo > span > span {
            color: var(--pink);
        }

        .nav-links {
            display: flex;
            gap: 24px;
            align-items: center;
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
            color: var(--pink) !important;
            border: 1px solid var(--pink);
            border-radius: 9px;
            background: rgba(255, 79, 154, 0.04);
        }

        .logout:hover {
            background: var(--pink);
            color: white !important;
            box-shadow: 0 0 20px var(--pink-glow);
        }

        .container {
            width: min(940px, calc(100% - 300px));
            margin: 0 20px 0 max(260px, calc((100% - 1200px) / 2 + 245px));
            padding: 130px 0 90px;
        }

        .heading {
            margin-bottom: 30px;
        }

        .label {
            color: var(--pink);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2px;
        }

        .heading h1 {
            margin: 10px 0;
            font-size: clamp(30px, 5vw, 45px);
        }

        .heading h1 span {
            color: var(--pink);
        }

        .heading p {
            color: var(--muted);
        }

        .history-card {
            overflow: hidden;
            border-radius: 20px;
            background: linear-gradient(180deg, var(--card) 0%, var(--card-strong) 100%);
            border: 1px solid var(--border);
            box-shadow: 0 25px 80px rgba(0, 0, 0, 0.25);
        }

        body.light-mode .history-card {
            box-shadow: 0 18px 40px var(--shadow);
        }

        .table-wrapper {
            overflow-x: auto;
        }

        table {
            width: 100%;
            min-width: 900px;
            border-collapse: collapse;
        }

        th {
            padding: 18px 20px;
            text-align: left;
            color: var(--muted);
            font-size: 10px;
            letter-spacing: 1px;
            background: rgba(255, 255, 255, 0.02);
        }

        td {
            padding: 18px 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            color: var(--text);
            font-size: 13px;
        }

        body.light-mode td {
            border-top-color: rgba(255, 79, 154, 0.08);
        }

        .file {
            color: var(--text);
            font-weight: 600;
        }

        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 0.7px;
        }

        .badge.safe {
            color: var(--safe);
            background: rgba(66, 245, 158, 0.1);
        }

        .badge.suspicious {
            color: var(--warning);
            background: rgba(255, 200, 87, 0.1);
        }

        .badge.malicious {
            color: var(--danger);
            background: rgba(255, 101, 117, 0.12);
        }

        .score {
            color: var(--pink-light);
            font-weight: 700;
        }

        .view {
            color: var(--pink-light);
            text-decoration: none;
            font-weight: 600;
        }

        .view:hover {
            color: var(--pink);
        }

        .empty {
            padding: 70px 20px;
            text-align: center;
            color: var(--muted);
        }

        .empty i {
            font-size: 40px;
            margin-bottom: 15px;
            color: var(--pink);
        }

        .empty h2 {
            color: var(--text);
        }

        @media (max-width: 900px) {
            .nav-links a:not(.logout) {
                display: none;
            }

            .navbar {
                padding: 0 24px;
            }

            .container {
                width: 92%;
                margin: auto;
                padding: 32px 0 70px;
            }
        }

    </style>

    <link rel="stylesheet" href="assets/css/workspace-sidebar.css">

</head>


<body>


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
$workspaceSidebarFixedHeader = true;
require __DIR__ . "/includes/workspace_sidebar.php";
?>


<main class="container">

    <div class="heading">

        <span class="label">
            SECURITY RECORDS
        </span>

        <h1>
            Scan <span>History</span>
        </h1>

        <p>
            Review your previous file analysis results.
        </p>

    </div>


    <div class="history-card">


        <?php if ($scans->num_rows > 0): ?>


            <div class="table-wrapper">

                <table>

                    <thead>

                        <tr>

                            <th>
                                FILE
                            </th>

                            <th>
                                TYPE
                            </th>

                            <th>
                                SIZE
                            </th>

                            <th>
                                STATUS
                            </th>

                            <th>
                                THREAT
                            </th>

                            <th>
                                SCORE
                            </th>

                            <th>
                                DETECTIONS
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
                        $scan = $scans->fetch_assoc()
                    ): ?>


                        <tr>


                            <td>

                                <span class="file">

                                    <?= e(
                                        $scan["original_file_name"]
                                    ) ?>

                                </span>

                            </td>


                            <td>

                                <?= e(
                                    $scan["file_extension"] ??
                                    ""
                                ) ?>

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

                                <?= e(
                                    strtoupper(
                                        $scan["threat_level"]
                                    )
                                ) ?>

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

                                <?= (int)$scan[
                                    "detection_count"
                                ] ?>

                            </td>


                            <td>

                                <?= e(
                                    $scan["scanned_at"]
                                ) ?>

                            </td>


                            <td>

                                <a
                                    class="view"
                                    href="results.php?id=<?= (int)$scan["id"] ?>"
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

                <i class="fa-solid fa-clock-rotate-left"></i>

                <h2>
                    No Scan History
                </h2>

                <p>
                    Your completed scans will appear here.
                </p>

            </div>


        <?php endif; ?>


    </div>


</main>

    <script src="assets/js/script.js"></script>

</body>

</html>

<?php

$stmt->close();

$conn->close();

?>
