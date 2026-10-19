<?php

session_start();

require_once __DIR__ . DIRECTORY_SEPARATOR . "app_config.php";
require_once "db.php";

/*
|--------------------------------------------------------------------------
| Check login
|--------------------------------------------------------------------------
*/

if (
    !isset($_SESSION["logged_in"]) ||
    $_SESSION["logged_in"] !== true
) {
    header("Location: login.html?role=user");
    exit;
}


/*
|--------------------------------------------------------------------------
| Get scan ID
|--------------------------------------------------------------------------
*/

$scanId = filter_input(
    INPUT_GET,
    "id",
    FILTER_VALIDATE_INT
);

if (!$scanId) {
    die("Invalid scan ID.");
}


/*
|--------------------------------------------------------------------------
| Get scan
|--------------------------------------------------------------------------
*/

$userId = $_SESSION["user_id"];

$stmt = $conn->prepare(
    "SELECT
        id,
        file_name,
        original_file_name,
        file_size,
        file_type,
        file_extension,
        file_hash,
        threat_level,
        detection_status,
        security_score,
        detection_count,
        analysis_result,
        scan_engine,
        scanned_at,
        created_at,
        vt_status,
        vt_malicious,
        vt_engines,
        detection_source,
        recommended_action
     FROM scans
     WHERE id = ?
     AND user_id = ?
     LIMIT 1"
);

$stmt->bind_param(
    "ii",
    $scanId,
    $userId
);

$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows !== 1) {

    $stmt->close();
    $conn->close();

    die("Scan not found.");

}

$scan = $result->fetch_assoc();

$stmt->close();


/*
|--------------------------------------------------------------------------
| Get detection findings
|--------------------------------------------------------------------------
*/

$findings = [];

$stmt = $conn->prepare(
    "SELECT
        id,
        detection_type,
        detection_name,
        severity,
        description,
        evidence,
        score,
        created_at
     FROM detection_results
     WHERE scan_id = ?
     ORDER BY id ASC"
);

$stmt->bind_param(
    "i",
    $scanId
);

$stmt->execute();

$findingsResult = $stmt->get_result();

while ($row = $findingsResult->fetch_assoc()) {
    $findings[] = $row;
}

$stmt->close();

$conn->close();


/*
|--------------------------------------------------------------------------
| Helper functions
|--------------------------------------------------------------------------
*/

function formatBytes($bytes)
{
    if ($bytes <= 0) {
        return "0 Bytes";
    }

    $units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];

    $power = floor(
        log($bytes, 1024)
    );

    $power = min(
        $power,
        count($units) - 1
    );

    return round(
        $bytes / pow(1024, $power),
        2
    ) . " " . $units[$power];
}


function threatClass($level)
{
    switch ($level) {

        case "safe":
            return "safe";

        case "low":
            return "low";

        case "medium":
            return "medium";

        case "high":
            return "high";

        case "critical":
            return "critical";

        default:
            return "unknown";
    }
}


function statusLabel($status)
{
    switch ($status) {

        case "safe":
            return "SAFE";

        case "suspicious":
            return "SUSPICIOUS";

        case "malicious":
            return "MALICIOUS";

        case "pending":
            return "PENDING";

        case "scanning":
            return "SCANNING";

        case "error":
            return "ERROR";

        default:
            return strtoupper($status);
    }
}


function escape($value)
{
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES,
        "UTF-8"
    );
}


function buildAiSummary(array $scan): ?string
{
    $apiKey = malwareGuardSetting("OPENAI_API_KEY");
    if ($apiKey === "" || !function_exists("curl_init")) {
        return null;
    }

    $findings = [];
    foreach ($scan["findings"] ?? [] as $finding) {
        $findings[] = [
            "name" => $finding["name"] ?? "Finding",
            "severity" => $finding["severity"] ?? "unknown",
            "description" => $finding["description"] ?? "No description provided."
        ];
    }

    $topFindings = array_slice($findings, 0, 3);
    $payload = [
        "model" => "gpt-4o-mini",
        "messages" => [[
            "role" => "system",
            "content" => "You are a cautious malware triage assistant. Create a short but specific summary for a user reviewing a suspicious file. Use only the metadata given below. Explain the likely risk, why the file is treated that way, and what the user should do next. Include a brief risk interpretation, a clear recommendation, and a note that this is based on static analysis and optional third-party reputation data rather than certainty. Keep it to 4-6 sentences and avoid making unsupported claims."
        ], [
            "role" => "user",
            "content" => json_encode([
                "fileName" => $scan["original_file_name"] ?? "unknown",
                "fileType" => $scan["file_type"] ?? "unknown",
                "status" => $scan["detection_status"] ?? "unknown",
                "threatLevel" => $scan["threat_level"] ?? "unknown",
                "securityScore" => (float) ($scan["security_score"] ?? 0),
                "findingCount" => (int) ($scan["detection_count"] ?? 0),
                "topFindings" => $topFindings,
                "recommendedAction" => "Use a sandbox, isolate the file, and verify the source before opening or executing it."
            ])
        ]],
        "temperature" => 0.2
    ];

    $curl = curl_init("https://api.openai.com/v1/chat/completions");
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => [
            "Authorization: Bearer " . $apiKey,
            "Content-Type: application/json",
            "Accept: application/json"
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS
    ]);

    $response = curl_exec($curl);
    $httpStatus = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if (!is_string($response) || $httpStatus !== 200) {
        return null;
    }

    $decoded = json_decode($response, true);
    $content = $decoded["choices"][0]["message"]["content"] ?? null;

    return is_string($content) && trim($content) !== "" ? trim($content) : null;
}


$aiSummary = buildAiSummary([
    "original_file_name" => $scan["original_file_name"] ?? "unknown",
    "file_type" => $scan["file_type"] ?? "unknown",
    "detection_status" => $scan["detection_status"] ?? "unknown",
    "threat_level" => $scan["threat_level"] ?? "unknown",
    "security_score" => $scan["security_score"] ?? 0,
    "detection_count" => $scan["detection_count"] ?? 0,
    "findings" => $findings
]);


$levelClass =
    threatClass(
        $scan["threat_level"]
    );

$statusLabel =
    statusLabel(
        $scan["detection_status"]
    );

$score =
    (float)$scan["security_score"];

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
        Scan Result | MalwareGuard
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
            font-family: "Segoe UI", Arial, sans-serif;
            background: radial-gradient(circle at 75% 20%, rgba(255, 79, 154, 0.12), transparent 35%), var(--background);
            color: var(--text);
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
            --shadow: rgba(214, 142, 176, 0.18);
            background: linear-gradient(180deg, #fff9fb 0%, #f6edf3 100%);
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
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 6%;
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
            font-size: 21px;
            font-weight: 700;
        }

        .logo > span > span {
            color: var(--pink);
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

        .nav-links {
            display: flex;
            align-items: center;
            gap: 25px;
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

        .login-btn {
            padding: 10px 17px;
            border-radius: 9px;
            color: var(--pink) !important;
            border: 1px solid var(--pink);
            background: rgba(255, 79, 154, 0.04);
        }

        .login-btn:hover {
            background: var(--pink);
            color: white !important;
            box-shadow: 0 0 20px var(--pink-glow);
        }

        .page {
            width: min(940px, calc(100% - 300px));
            margin: 0 20px 0 max(260px, calc((100% - 1200px) / 2 + 245px));
            padding: 120px 0 100px;
        }

        .heading {
            text-align: center;
            margin-bottom: 35px;
        }

        .label {
            color: var(--pink);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 2px;
        }

        .heading h1 {
            margin: 12px 0;
            font-size: clamp(32px, 5vw, 52px);
        }

        .heading h1 span {
            color: var(--pink);
        }

        .heading p {
            color: var(--muted);
            margin: 0;
        }

        .result-card {
            background: linear-gradient(180deg, var(--card) 0%, var(--card-strong) 100%);
            border: 1px solid var(--border);
            border-radius: 22px;
            overflow: hidden;
            box-shadow: 0 25px 80px rgba(0, 0, 0, 0.35);
        }

        body.light-mode .result-card {
            box-shadow: 0 18px 40px var(--shadow);
        }

        .result-header {
            padding: 22px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        .result-header-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
            font-weight: 700;
        }

        .result-header-title i {
            color: var(--pink);
        }

        .status-pill {
            padding: 7px 13px;
            border-radius: 50px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
        }

        .status-pill.safe {
            color: var(--safe);
            background: rgba(66, 245, 158, 0.1);
        }

        .status-pill.suspicious,
        .status-pill.medium {
            color: var(--warning);
            background: rgba(255, 200, 87, 0.1);
        }

        .status-pill.malicious,
        .status-pill.high,
        .status-pill.critical {
            color: var(--danger);
            background: rgba(255, 92, 112, 0.1);
        }


        /* FILE */

        .file-section {
            padding: 30px;
        }


        .file-info {
            display: flex;
            align-items: center;
            gap: 18px;
        }


        .file-icon {
            width: 65px;
            height: 65px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 16px;

            color: var(--pink);

            background:
                rgba(255, 79, 154, 0.08);

            font-size: 25px;
        }


        .file-info h2 {
            margin: 0 0 5px;

            font-size: 20px;

            word-break: break-word;
        }


        .file-info p {
            margin: 0;

            color: var(--muted);

            font-size: 13px;
        }


        /* MAIN RESULT */

        .main-result {
            margin-top: 30px;

            display: grid;

            grid-template-columns:
                1fr 1fr;

            gap: 25px;
        }


        .result-status {
            min-height: 230px;

            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;

            text-align: center;

            border-radius: 18px;

            background:
                rgba(255,255,255,0.025);
        }


        .result-status-icon {
            width: 75px;
            height: 75px;

            display: flex;
            align-items: center;
            justify-content: center;

            border-radius: 50%;

            font-size: 30px;

            margin-bottom: 15px;
        }


        .result-status.safe .result-status-icon {
            color: var(--safe);

            background:
                rgba(66,245,158,0.1);
        }


        .result-status.suspicious .result-status-icon,
        .result-status.malicious .result-status-icon {
            color: var(--danger);

            background:
                rgba(255,104,120,0.1);
        }


        .result-status h2 {
            margin: 0;

            font-size: 30px;
        }


        .result-status p {
            color: var(--muted);

            margin: 8px 20px 0;

            line-height: 1.6;
        }


        /* SCORE */

        .score-panel {
            padding: 28px;

            border-radius: 18px;

            background:
                rgba(255,255,255,0.025);
        }


        .score-title {
            color: var(--muted);

            font-size: 12px;

            letter-spacing: 1.5px;

            font-weight: 700;
        }


        .score-value {
            display: flex;
            justify-content: space-between;
            align-items: end;

            margin: 12px 0 15px;
        }


        .score-value strong {
            font-size: 50px;

            color: var(--pink-light);
        }


        .score-value span {
            color: var(--muted);

            font-size: 13px;
        }


        .progress {
            width: 100%;
            height: 10px;

            overflow: hidden;

            border-radius: 20px;

            background:
                rgba(255, 255, 255, 0.08);
        }


        .progress-bar {
            height: 100%;

            width: <?= min(100, max(0, $score)) ?>%;

            border-radius: inherit;

            background:
                linear-gradient(
                    90deg,
                    var(--pink-dark),
                    var(--pink)
                );
        }


        /* DETAILS */

        .details {
            margin-top: 25px;

            display: grid;

            grid-template-columns:
                repeat(4, 1fr);

            gap: 12px;
        }

        .ai-summary,
        .info-note,
        .recommendation-card {
            grid-column: 1 / -1;
            padding: 18px 20px;
            border-radius: 14px;
            border: 1px solid rgba(255, 79, 154, 0.18);
            background: rgba(255, 79, 154, 0.05);
        }

        .ai-summary-header,
        .recommendation-title {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            color: var(--pink);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .ai-summary p,
        .info-note p,
        .recommendation-card p {
            margin: 0;
            color: var(--muted);
            line-height: 1.7;
        }

        .detail {
            padding: 18px;

            border-radius: 14px;

            background:
                rgba(255,255,255,0.025);

            border:
                1px solid rgba(255,255,255,0.05);
        }


        .detail span {
            display: block;

            color: var(--muted);

            font-size: 11px;

            margin-bottom: 7px;
        }


        .detail strong {
            display: block;

            font-size: 13px;

            word-break: break-word;
        }


        /* FINDINGS */

        .findings {
            margin-top: 25px;

            padding: 30px;

            border-top:
                1px solid rgba(255,255,255,0.06);
        }


        .findings h2 {
            margin-top: 0;

            font-size: 20px;
        }


        .finding {
            padding: 18px;

            margin-top: 12px;

            border-radius: 14px;

            background:
                rgba(255,255,255,0.025);

            border:
                1px solid rgba(255,255,255,0.05);
        }


        .finding-top {
            display: flex;
            justify-content: space-between;
            gap: 15px;
        }


        .finding-name {
            font-weight: 700;
        }


        .severity {
            font-size: 10px;

            font-weight: 800;

            letter-spacing: 1px;

            padding: 5px 9px;

            border-radius: 20px;
        }


        .severity.info {
            color: var(--pink-light);

            background:
                rgba(255, 128, 181, 0.12);
        }


        .severity.low {
            color: var(--pink-light);

            background:
                rgba(255, 128, 181, 0.12);
        }


        .severity.medium {
            color: var(--warning);

            background:
                rgba(255,200,87,0.1);
        }


        .severity.high,
        .severity.critical {
            color: var(--danger);

            background:
                rgba(255,101,118,0.1);
        }


        .finding p {
            color: var(--muted);

            line-height: 1.6;

            font-size: 13px;
        }


        .evidence {
            color: var(--muted);

            font-family: monospace;

            font-size: 12px;

            word-break: break-all;
        }


        .no-findings {
            padding: 20px;

            text-align: center;

            color: #6e7d90;

            border-radius: 14px;

            background:
                rgba(66,245,158,0.04);
        }


        /* BUTTONS */

        .actions {
            display: flex;

            justify-content: center;

            gap: 15px;

            margin-top: 30px;
        }


        .btn {
            display: inline-flex;

            align-items: center;

            gap: 9px;

            padding: 13px 20px;

            border-radius: 10px;

            text-decoration: none;

            font-weight: 700;

            font-size: 13px;
        }


        .btn-primary {
            color: white;

            background: linear-gradient(135deg, var(--pink), var(--pink-dark));
            box-shadow: 0 0 25px var(--pink-glow);
        }


        .btn-secondary {
            color: var(--muted);

            border:
                1px solid var(--border);
            background: rgba(255,255,255,0.02);
        }


        @media (max-width: 800px) {

            .nav-links a:not(.login-btn) {
                display: none;
            }

            .page {
                width: 92%;
                margin: auto;
                padding: 32px 0 70px;
            }

            .main-result {
                grid-template-columns: 1fr;
            }

            .details {
                grid-template-columns:
                    repeat(2, 1fr);
            }

        }


        @media (max-width: 500px) {

            .page {
                width: 94%;
            }

            .file-section,
            .findings {
                padding: 20px;
            }

            .details {
                grid-template-columns: 1fr;
            }

            .actions {
                flex-direction: column;
            }

            .btn {
                justify-content: center;
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
            class="login-btn"
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


<main class="page">


    <!-- HEADING -->

    <div class="heading">

        <span class="label">
            SCAN COMPLETED
        </span>

        <h1>
            File <span>Analysis</span>
        </h1>

        <p>
            Results from the MalwareGuard static analysis engine.
        </p>

    </div>


    <!-- RESULT CARD -->

    <div class="result-card">


        <!-- HEADER -->

        <div class="result-header">

            <div class="result-header-title">

                <i class="fa-solid fa-file-shield"></i>

                FILE ANALYSIS RESULT

            </div>


            <span
                class="status-pill <?= escape($levelClass) ?>"
            >
                <?= escape($statusLabel) ?>
            </span>

        </div>


        <!-- FILE -->

        <div class="file-section">

            <div class="file-info">

                <div class="file-icon">

                    <i class="fa-solid fa-file"></i>

                </div>


                <div>

                    <h2>
                        <?= escape(
                            $scan["original_file_name"]
                        ) ?>
                    </h2>

                    <p>

                        <?= escape(
                            strtoupper(
                                $scan["file_extension"] ?: "FILE"
                            )
                        ) ?>

                        &nbsp; • &nbsp;

                        <?= formatBytes(
                            $scan["file_size"]
                        ) ?>

                    </p>

                </div>

            </div>


            <!-- MAIN RESULT -->

            <div class="main-result">


                <!-- STATUS -->

                <div
                    class="result-status <?= escape($scan["detection_status"]) ?>"
                >

                    <div class="result-status-icon">

                        <?php if (
                            $scan["detection_status"] === "safe"
                        ): ?>

                            <i class="fa-solid fa-check"></i>

                        <?php else: ?>

                            <i class="fa-solid fa-triangle-exclamation"></i>

                        <?php endif; ?>

                    </div>


                    <h2>
                        <?= escape($statusLabel) ?>
                    </h2>


                    <p>
                        <?= escape(
                            $scan["analysis_result"]
                        ) ?>
                    </p>

                    <?php if (!empty($scan["recommended_action"])): ?>
                        <p><strong>Recommended next action:</strong> <?= escape($scan["recommended_action"]) ?></p>
                    <?php endif; ?>

                    <p>
                        <strong>Detection ratio:</strong>
                        <?= ($scan["vt_status"] ?? "") === "found"
                            ? escape($scan["vt_malicious"] . "/" . $scan["vt_engines"]) . " VirusTotal engines"
                            : "not available (" . escape(str_replace("_", " ", (string) ($scan["vt_status"] ?? "not checked"))) . ")" ?>
                        &middot; <strong>Source:</strong> <?= escape($scan["detection_source"] ?? "MalwareGuard static rules") ?>
                    </p>

                </div>


                <!-- SCORE -->

                <div class="score-panel">

                    <span class="score-title">
                        SECURITY SCORE
                    </span>


                    <div class="score-value">

                        <strong>
                            <?= number_format(
                                $score,
                                0
                            ) ?>%
                        </strong>

                        <span>
                            Rule-based score: 100 minus matched indicator points. Not a probability.
                        </span>

                    </div>


                    <div class="progress">

                        <div class="progress-bar"></div>

                    </div>

                </div>

            </div>


            <!-- DETAILS -->

            <div class="details">


                <div class="detail">

                    <span>
                        THREAT LEVEL
                    </span>

                    <strong>
                        <?= escape(
                            strtoupper(
                                $scan["threat_level"]
                            )
                        ) ?>
                    </strong>

                </div>


                <div class="detail">

                    <span>
                        DETECTIONS
                    </span>

                    <strong>
                        <?= escape(
                            $scan["detection_count"]
                        ) ?>
                    </strong>

                </div>


                <div class="detail">

                    <span>
                        FILE TYPE
                    </span>

                    <strong>
                        <?= escape(
                            $scan["file_type"]
                        ) ?>
                    </strong>

                </div>


                <div class="detail">

                    <span>
                        SCAN ENGINE
                    </span>

                    <strong>
                        <?= escape(
                            $scan["scan_engine"]
                        ) ?>
                    </strong>

                </div>

                <?php if ($aiSummary): ?>
                    <div class="ai-summary">
                        <div class="ai-summary-header">
                            <i class="fa-solid fa-wand-sparkles"></i>
                            AI SECURITY SUMMARY
                        </div>
                        <p><?= escape($aiSummary) ?></p>
                    </div>
                <?php elseif (malwareGuardSetting("OPENAI_API_KEY", "") === ""): ?>
                    <div class="info-note">
                        <div class="ai-summary-header">
                            <i class="fa-solid fa-circle-info"></i>
                            OPTIONAL AI SUMMARY
                        </div>
                        <p>OpenAI integration is not configured. Add OPENAI_API_KEY to .env to enable the plain-language summary on this result.</p>
                    </div>
                <?php endif; ?>

                <div class="recommendation-card">
                    <div class="recommendation-title">
                        <i class="fa-solid fa-circle-exclamation"></i>
                        RECOMMENDED ACTION
                    </div>
                    <p>
                        <?php
                        $recommendation = "Isolate the file, verify the source, and avoid opening or executing it until a trusted baseline confirms it is safe.";
                        if ($scan["detection_status"] === "safe") {
                            $recommendation = "No strong indicators were found. Keep the file in a monitored environment and perform a normal verification before trusting it.";
                        } elseif ($scan["detection_status"] === "suspicious") {
                            $recommendation = "Review the file in a sandbox and validate the source before opening it. Restrict execution and scan it again with a trusted environment.";
                        } elseif ($scan["detection_status"] === "malicious") {
                            $recommendation = "Quarantine the file immediately, remove any related downloads or scripts, and investigate the source before retrying anything from that origin.";
                        }
                        echo escape($recommendation);
                        ?>
                    </p>
                </div>

                <div class="detail">

                    <span>
                        SCAN TIME
                    </span>

                    <strong>
                        <?= escape(
                            $scan["scanned_at"]
                        ) ?>
                    </strong>

                </div>


                <div
                    class="detail"
                    style="grid-column: span 2;"
                >

                    <span>
                        SHA-256 HASH
                    </span>

                    <strong
                        style="
                            font-family:monospace;
                            font-size:11px;
                        "
                    >
                        <?= escape(
                            $scan["file_hash"]
                        ) ?>
                    </strong>

                </div>


            </div>

        </div>


        <!-- FINDINGS -->

        <div class="findings">

            <h2>
                Detection Findings
            </h2>


            <?php if (empty($findings)): ?>

                <div class="no-findings">

                    <i
                        class="fa-solid fa-circle-check"
                        style="
                            color:#42f59e;
                            margin-right:8px;
                        "
                    ></i>

                    No configured suspicious indicators
                    were detected.

                </div>

            <?php else: ?>


                <?php foreach (
                    $findings as $finding
                ): ?>


                    <div class="finding">

                        <div class="finding-top">

                            <span class="finding-name">

                                <?= escape(
                                    $finding["detection_name"]
                                ) ?>

                            </span>


                            <span
                                class="severity <?= escape(
                                    $finding["severity"]
                                ) ?>"
                            >

                                <?= escape(
                                    strtoupper(
                                        $finding["severity"]
                                    )
                                ) ?>

                            </span>

                        </div>


                        <p>

                            <?= escape(
                                $finding["description"]
                            ) ?>

                        </p>


                        <?php if (
                            !empty(
                                $finding["evidence"]
                            )
                        ): ?>

                            <div class="evidence">

                                Evidence:
                                <?= escape(
                                    $finding["evidence"]
                                ) ?>

                            </div>

                        <?php endif; ?>


                    </div>


                <?php endforeach; ?>


            <?php endif; ?>


        </div>


    </div>


    <!-- ACTIONS -->

    <div class="actions">

        <a
            href="scan.php"
            class="btn btn-primary"
        >

            <i class="fa-solid fa-shield-virus"></i>

            Scan Another File

        </a>


        <a
            href="history.php"
            class="btn btn-secondary"
        >

            <i class="fa-solid fa-clock-rotate-left"></i>

            Scan History

        </a>


        <a
            href="dashboard.php"
            class="btn btn-secondary"
        >

            <i class="fa-solid fa-gauge-high"></i>

            Dashboard

        </a>

    </div>


</main>


    <script src="assets/js/script.js"></script>

</body>

</html>
