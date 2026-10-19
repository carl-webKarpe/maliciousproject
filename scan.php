<?php

session_start();

if (
    !isset($_SESSION["logged_in"]) ||
    $_SESSION["logged_in"] !== true
) {
    header("Location: login.html");
    exit;
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Scan File | MalwareGuard</title>

    <link rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <style>
        :root {
            --pink: #ff4f9a;
            --pink-light: #ff80b5;
            --pink-dark: #d9367c;
            --pink-glow: rgba(255, 79, 154, 0.35);
            --background: #0b0710;
            --background-light: #130b16;
            --card: #160d19;
            --border: #3a1c32;
            --text: #f8eaf2;
            --muted: #a8909d;
            --panel: rgba(255, 255, 255, 0.03);
            --soft-panel: rgba(255, 255, 255, 0.02);
            --shadow: rgba(0, 0, 0, 0.3);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            color: var(--text);
            background: radial-gradient(circle at 75% 20%, rgba(255, 79, 154, 0.12), transparent 35%), var(--background);
        }

        body.light-mode {
            --pink: #e53689;
            --pink-light: #ff7abc;
            --pink-dark: #b72267;
            --pink-glow: rgba(229, 54, 137, 0.18);
            --background: #f7f0f5;
            --background-light: #fff6fb;
            --card: #ffffff;
            --border: #f0d6e7;
            --text: #1e1320;
            --muted: #625164;
            --panel: rgba(255, 255, 255, 0.8);
            --soft-panel: rgba(255, 255, 255, 0.7);
            --shadow: rgba(214, 142, 176, 0.18);
            background: linear-gradient(180deg, #fff9fb 0%, #f6edf3 100%);
        }

        .theme-toggle {
            position: fixed;
            top: 90px;
            right: 22px;
            width: 48px;
            height: 48px;
            border: 1px solid var(--border);
            border-radius: 50%;
            background: rgba(16, 13, 22, 0.78);
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.18);
            z-index: 50;
        }

        body.light-mode .theme-toggle {
            background: rgba(255, 255, 255, 0.9);
        }

        .navbar {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 75px;
            padding: 0 7%;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(11, 7, 16, 0.55);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid transparent;
            z-index: 30;
        }

        body.light-mode .navbar {
            background: rgba(255, 255, 255, 0.9);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 22px;
            font-weight: 700;
        }

        .logo span span {
            color: var(--pink);
        }

        .logo-shield {
            width: 38px;
            height: 38px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--pink);
            border: 1px solid var(--pink);
            border-radius: 10px;
            box-shadow: 0 0 15px var(--pink-glow);
        }

        .nav-links {
            display: flex;
            align-items: center;
            gap: 28px;
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
            padding: 10px 20px;
            border: 1px solid var(--pink);
            border-radius: 8px;
            color: var(--pink) !important;
            transition: 0.3s;
        }

        .login-btn:hover {
            background: var(--pink);
            color: white !important;
            box-shadow: 0 0 20px var(--pink-glow);
        }

        .scanner-page {
            width: min(940px, calc(100% - 300px));
            margin: 0 20px 0 max(260px, calc((100% - 1200px) / 2 + 245px));
            padding: 100px 0 80px;
        }

        .scanner-heading {
            text-align: center;
            margin-bottom: 32px;
        }

        .section-label {
            color: var(--pink);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2px;
        }

        .scanner-heading h1 {
            margin-top: 8px;
            font-size: clamp(36px, 4vw, 52px);
            line-height: 1.1;
        }

        .scanner-heading h1 span {
            color: var(--pink);
        }

        .scanner-heading p {
            margin-top: 12px;
            color: var(--muted);
            font-size: 15px;
        }

        .scanner-card {
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.97), rgba(17, 9, 20, 0.97));
            border: 1px solid var(--border);
            border-radius: 22px;
            padding: 28px;
            box-shadow: 0 25px 80px rgba(0, 0, 0, 0.35);
        }

        body.light-mode .scanner-card,
        body.light-mode .security-notice {
            background: linear-gradient(145deg, rgba(255,255,255,0.96), rgba(255,244,250,0.97));
            border-color: var(--border);
            box-shadow: 0 18px 40px var(--shadow);
        }

        .drop-zone {
            border: 1.5px dashed var(--border);
            border-radius: 18px;
            min-height: 310px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            gap: 12px;
            background: rgba(255, 255, 255, 0.02);
            padding: 28px;
            transition: 0.3s ease;
            cursor: pointer;
        }

        .drop-zone.dragging,
        .drop-zone:hover {
            border-color: var(--pink);
            background: rgba(255, 79, 154, 0.04);
        }

        .upload-icon {
            width: 72px;
            height: 72px;
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
            color: var(--pink);
            background: rgba(255, 79, 154, 0.08);
            border: 1px solid rgba(255, 79, 154, 0.2);
        }

        .drop-zone h2 {
            font-size: clamp(24px, 3vw, 34px);
            letter-spacing: 0.08em;
        }

        .drop-zone p,
        .drop-zone span {
            color: var(--muted);
        }

        .primary-btn,
        .scan-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--pink), var(--pink-dark));
            color: white;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 0 25px var(--pink-glow);
            transition: 0.3s ease;
        }

        .primary-btn {
            margin-top: 8px;
            padding: 14px 20px;
        }

        .scan-btn {
            margin-top: 24px;
            width: 100%;
            height: 54px;
            font-size: 15px;
        }

        .scan-btn:disabled {
            cursor: wait;
            opacity: 0.8;
            transform: none;
        }

        .scan-btn .fa-spin {
            animation-duration: 4.5s;
        }

        .scan-status {
            position: fixed;
            inset: 0;
            z-index: 1000;
            display: grid;
            place-items: center;
            padding: 24px;
            background: rgba(11, 7, 16, 0.88);
            backdrop-filter: blur(8px);
        }

        .scan-status[hidden] {
            display: none;
        }

        .scan-status:not([hidden]) {
            animation: scan-overlay-in 500ms ease-out both;
        }

        .scan-status-panel {
            width: min(440px, 100%);
            padding: 34px;
            border: 1px solid var(--border);
            border-radius: 16px;
            background: linear-gradient(145deg, rgba(22, 13, 25, 0.99), rgba(17, 9, 20, 0.99));
            box-shadow: 0 25px 80px rgba(0, 0, 0, 0.5), 0 0 35px rgba(255, 79, 154, 0.08);
            text-align: center;
            animation: scan-panel-in 600ms ease-out both;
        }

        .scan-status-text {
            display: grid;
            justify-items: center;
            gap: 16px;
            color: var(--text);
            font-weight: 600;
            font-size: 18px;
        }

        .scan-status-text i {
            color: var(--pink);
            font-size: 38px;
        }

        .scan-status p {
            margin: 12px 0 0;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.5;
        }

        .scan-progress {
            height: 4px;
            margin-top: 14px;
            overflow: hidden;
            border-radius: 4px;
            background: rgba(255, 79, 154, 0.14);
        }

        .scan-progress-fill {
            display: block;
            width: 0;
            height: 100%;
            border-radius: inherit;
            background: linear-gradient(90deg, var(--pink-dark), var(--pink-light));
            transition: width 160ms ease-out;
        }

        .scan-error {
            margin: 14px 0 0;
            color: var(--danger);
            font-size: 13px;
            line-height: 1.5;
        }

        @keyframes scan-overlay-in {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes scan-panel-in {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (prefers-reduced-motion: reduce) {
            .scan-status:not([hidden]),
            .scan-status-panel { animation: none; }
            .scan-btn .fa-spin { animation: none; }
        }

        .primary-btn:hover,
        .scan-btn:hover {
            transform: translateY(-2px);
        }

        .selected-file {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 20px;
            padding: 14px 16px;
            border-radius: 12px;
            background: rgba(255, 79, 154, 0.06);
            border: 1px solid var(--border);
            color: var(--text);
            font-weight: 600;
        }

        .selected-file i {
            color: var(--pink);
        }

        .security-notice {
            margin-top: 28px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
            border-radius: 16px;
            border: 1px solid var(--border);
            background: rgba(255, 255, 255, 0.02);
            padding: 18px 20px;
        }

        .security-notice i {
            color: var(--pink);
            font-size: 22px;
            margin-top: 2px;
        }

        .security-notice strong {
            display: block;
            margin-bottom: 6px;
        }

        .security-notice p {
            color: var(--muted);
            line-height: 1.6;
        }

        @media (max-width: 900px) {
            .scanner-page {
                width: 92%;
                margin: auto;
                padding: 32px 0 70px;
            }
        }

        @media (max-width: 700px) {
            .nav-links a:not(.login-btn) {
                display: none;
            }

            .scanner-card {
                padding: 20px 18px;
            }

            .drop-zone {
                min-height: 260px;
            }
        }
    </style>

    <link rel="stylesheet" href="assets/css/workspace-sidebar.css">

</head>

<body<?php echo in_array($_SESSION["user_role"] ?? "", ["admin", "super_admin"], true) ? ' class="admin-workspace"' : ""; ?>>

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
        <a href="logout.php"
           class="login-btn">

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
$workspaceSidebarCompact = true;
require __DIR__ . "/includes/workspace_sidebar.php";
?>


<main class="scanner-page">

    <div class="scanner-heading">

        <span class="section-label">
            ENDPOINT DETECTION
        </span>

        <h1>
            Analyze Your
            <span>File</span>
        </h1>

        <p>
            Upload a file for static security analysis.
        </p>

    </div>


    <div class="scanner-card">

        <form
            action="upload.php"
            method="POST"
            enctype="multipart/form-data"
            id="scanForm"
        >

            <div
                class="drop-zone"
                id="dropZone"
            >

                <div class="upload-icon">

                    <i class="fa-solid fa-cloud-arrow-up"></i>

                </div>

                <h2>
                    DROP YOUR FILE HERE
                </h2>

                <p>
                    or click to browse
                </p>

                <span>
                    Maximum file size: 50 MB
                </span>


                <input
                    type="file"
                    id="fileInput"
                    name="scan_file"
                    hidden
                    required
                >


                <button
                    type="button"
                    class="primary-btn"
                    onclick="document.getElementById('fileInput').click()"
                >

                    <i class="fa-solid fa-folder-open"></i>

                    Choose File

                </button>

            </div>


            <div
                id="selectedFile"
                class="selected-file"
                style="display:none;"
            >

                <i class="fa-solid fa-file"></i>

                <span id="fileName">
                    File
                </span>

            </div>


            <button
                type="submit"
                class="scan-btn"
                id="scanButton"
            >

                <i class="fa-solid fa-shield-virus"></i>

                <span id="scanButtonLabel">Analyze File</span>

            </button>

            <div class="scan-status" id="scanStatus" role="status" aria-live="polite" aria-busy="false" hidden>
                <div class="scan-status-panel">
                    <div class="scan-status-text">
                        <i class="fa-solid fa-shield-virus" aria-hidden="true"></i>
                        <span id="scanStatusText">Preparing your file...</span>
                    </div>
                    <p>Your score and safety result will appear when the scan is complete.</p>
                    <div class="scan-progress" id="scanProgress" role="progressbar" aria-label="File upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                        <span class="scan-progress-fill" id="scanProgressFill"></span>
                    </div>
                </div>
            </div>

            <p class="scan-error" id="scanError" role="alert" hidden></p>

        </form>

    </div>


    <div class="security-notice">

        <i class="fa-solid fa-circle-info"></i>

        <div>

            <strong>
                Security Notice
            </strong>

            <p>
                Files are analyzed using static security rules.
                Uploaded files are never executed by the scanner.
            </p>

        </div>

    </div>

</main>


<script>

const fileInput = document.getElementById("fileInput");

const dropZone = document.getElementById("dropZone");

const selectedFile = document.getElementById("selectedFile");

const fileName = document.getElementById("fileName");
const scanForm = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");
const scanButtonLabel = document.getElementById("scanButtonLabel");
const scanStatus = document.getElementById("scanStatus");
const scanStatusText = document.getElementById("scanStatusText");
const scanProgress = document.getElementById("scanProgress");
const scanProgressFill = document.getElementById("scanProgressFill");
const scanError = document.getElementById("scanError");
let analysisProgressTimer = null;

function setScanProgress(percent, description) {
    scanProgressFill.style.width = percent + "%";
    scanProgress.setAttribute("aria-valuenow", String(percent));
    scanProgress.setAttribute("aria-valuetext", description);
}

scanForm.addEventListener("submit", function (event) {
    event.preventDefault();
    clearInterval(analysisProgressTimer);
    analysisProgressTimer = null;
    scanError.hidden = true;
    scanButton.disabled = true;
    scanButtonLabel.textContent = "Scanning...";
    scanButton.querySelector("i").className = "fa-solid fa-spinner fa-spin";
    scanStatus.hidden = false;
    scanStatus.setAttribute("aria-busy", "true");

    scanStatusText.textContent = "Uploading file...";
    scanProgress.setAttribute("aria-label", "Estimated scan progress");
    setScanProgress(0, "File upload has not started");

    const request = new XMLHttpRequest();
    request.open("POST", scanForm.action);

    request.upload.addEventListener("progress", function (progressEvent) {
        if (!progressEvent.lengthComputable) return;

        const uploadPercent = Math.round((progressEvent.loaded / progressEvent.total) * 100);
        const overallPercent = Math.round(uploadPercent * 0.5);
        setScanProgress(overallPercent, "Upload " + uploadPercent + "% complete; analysis has not started");
        scanStatusText.textContent = "Uploading file... " + uploadPercent + "%";
    });

    request.upload.addEventListener("load", function () {
        let estimatedPercent = 50;
        setScanProgress(estimatedPercent, "Analysis in progress; estimated " + estimatedPercent + "%");
        scanStatusText.textContent = "Analyzing file... " + estimatedPercent + "% estimated";

        analysisProgressTimer = setInterval(function () {
            if (estimatedPercent >= 90) {
                clearInterval(analysisProgressTimer);
                analysisProgressTimer = null;
                return;
            }

            estimatedPercent += 1;
            setScanProgress(estimatedPercent, "Analysis in progress; estimated " + estimatedPercent + "%");
            scanStatusText.textContent = "Analyzing file... " + estimatedPercent + "% estimated";
        }, 400);
    });

    request.addEventListener("load", function () {
        clearInterval(analysisProgressTimer);
        analysisProgressTimer = null;
        const responseUrl = new URL(request.responseURL || scanForm.action, window.location.href);
        const uploadUrl = new URL(scanForm.action, window.location.href);

        if (request.status >= 200 && request.status < 400 && responseUrl.pathname !== uploadUrl.pathname) {
            setScanProgress(100, "Scan complete");
            scanStatusText.textContent = "Scan complete. Opening results...";
            window.location.assign(responseUrl.href);
            return;
        }

        showScanError(request.responseText || "The scan could not be completed. Please try again.");
    });

    request.addEventListener("error", function () {
        showScanError("The upload was interrupted. Check your connection and try again.");
    });

    request.send(new FormData(scanForm));
});

function showScanError(message) {
    clearInterval(analysisProgressTimer);
    analysisProgressTimer = null;
    scanStatus.hidden = true;
    scanStatus.setAttribute("aria-busy", "false");
    scanButton.disabled = false;
    scanButtonLabel.textContent = "Analyze File";
    scanButton.querySelector("i").className = "fa-solid fa-shield-virus";
    scanError.textContent = message.trim().slice(0, 240);
    scanError.hidden = false;
}


fileInput.addEventListener("change", function () {

    if (this.files.length > 0) {

        const file = this.files[0];

        fileName.textContent =
            file.name +
            " (" +
            formatBytes(file.size) +
            ")";

        selectedFile.style.display = "flex";

    }

});


dropZone.addEventListener("dragover", function (event) {

    event.preventDefault();

    dropZone.classList.add("dragging");

});


dropZone.addEventListener("dragleave", function () {

    dropZone.classList.remove("dragging");

});


dropZone.addEventListener("drop", function (event) {

    event.preventDefault();

    dropZone.classList.remove("dragging");

    if (event.dataTransfer.files.length > 0) {

        fileInput.files =
            event.dataTransfer.files;

        const file =
            event.dataTransfer.files[0];

        fileName.textContent =
            file.name +
            " (" +
            formatBytes(file.size) +
            ")";

        selectedFile.style.display = "flex";

    }

});


function formatBytes(bytes) {

    if (bytes === 0) {
        return "0 Bytes";
    }

    const sizes = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];

    const i =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    return (
        parseFloat(
            (bytes / Math.pow(1024, i))
            .toFixed(2)
        ) +
        " " +
        sizes[i]
    );

}

</script>
<script src="assets/js/script.js"></script>
</body>
</html>
