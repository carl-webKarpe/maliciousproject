<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>MalwareGuard | Intelligent Malware Detection</title>

    <link rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <script src="https://cdn.tailwindcss.com"></script>

    <link rel="stylesheet" href="assets/css/site.css">
</head>

<body>

<!-- ================= NAVBAR ================= -->

<nav class="navbar" id="navbar">

    <div class="logo">
        <div class="logo-shield">
            <i class="fa-solid fa-shield-halved"></i>
        </div>

        <span>Malware<span>Guard</span></span>
    </div>

    <div class="nav-links">
        <a href="#home">Home</a>
        <a href="#features">Features</a>
        <a href="#how-it-works">How It Works</a>
        <a href="#about">About</a>

        <a href="login.html" class="login-btn">
            <i class="fa-solid fa-right-to-bracket"></i>
            Login
        </a>
    </div>

    <button class="mobile-menu" onclick="toggleMenu()">
        <i class="fa-solid fa-bars"></i>
    </button>

    <button class="theme-toggle" type="button" aria-label="Switch to light mode">
        <i class="fa-solid fa-moon"></i>
    </button>

</nav>


<!-- ================= HERO ================= -->

<section class="hero" id="home">

    <div class="cyber-grid"></div>

    <div class="particles"></div>

    <div class="hero-content">

        <div class="status">
            <span class="status-dot"></span>
            SYSTEM SECURE
        </div>

        <h1>
            Intelligent
            <span>Malicious Software</span>
            Detection
        </h1>

        <h2>Detect. Analyze. Protect.</h2>

        <p>
            MalwareGuard helps identify potentially malicious files
            through intelligent security analysis, giving authorized
            users clear and understandable threat detection results.
        </p>

        <div class="hero-buttons">

            <a href="login.html" class="primary-btn">
                <i class="fa-solid fa-shield-virus"></i>
                Start Scanning
            </a>

            <a href="#how-it-works" class="secondary-btn">
                Learn More
                <i class="fa-solid fa-arrow-down"></i>
            </a>

        </div>

    </div>


    <!-- SECURITY VISUAL -->

    <div class="security-visual">

        <div class="security-ring ring-one"></div>
        <div class="security-ring ring-two"></div>

        <div class="scan-line"></div>

        <div class="security-shield">

            <div class="shield-glow"></div>

            <i class="fa-solid fa-shield-halved"></i>

            <div class="shield-text">
                <strong>MALWAREGUARD</strong>
                <small>THREAT ANALYSIS</small>
            </div>

        </div>

        <div class="security-node node-one">
            <i class="fa-solid fa-lock"></i>
        </div>

        <div class="security-node node-two">
            <i class="fa-solid fa-virus-slash"></i>
        </div>

        <div class="security-node node-three">
            <i class="fa-solid fa-file-shield"></i>
        </div>

    </div>

</section>


<!-- ================= FEATURES ================= -->

<section class="section" id="features">

    <div class="section-heading">

        <span class="section-label">SECURITY FEATURES</span>

        <h2>
            Powerful Security
            <span>Analysis</span>
        </h2>

        <p>
            MalwareGuard provides an easy-to-understand interface
            for analyzing files and viewing security results.
        </p>

    </div>


    <div class="features-grid">

        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-file-arrow-up"></i>
            </div>

            <h3>File Scanning</h3>

            <p>
                Upload and scan files for suspicious behavior, static indicators, and risk patterns.
            </p>

        </div>


        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-bug-slash"></i>
            </div>

            <h3>Threat Detection</h3>

            <p>
                Detect suspicious files and flag risky patterns before execution or unsafe use.
            </p>

        </div>


        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-chart-pie"></i>
            </div>

            <h3>Security Score</h3>

            <p>
                Review a clear security score that summarizes the confidence and severity of the result.
            </p>

        </div>


        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-shield-virus"></i>
            </div>

            <h3>Hash Reputation</h3>

            <p>
                Check file hash reputation through public intelligence sources to strengthen detection.
            </p>

        </div>


        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-wand-sparkles"></i>
            </div>

            <h3>AI Summary</h3>

            <p>
                Turn scan metadata into a readable explanation of the threat level and recommended action.
            </p>

        </div>


        <div class="feature-card">

            <div class="feature-icon">
                <i class="fa-solid fa-desktop"></i>
            </div>

            <h3>Endpoint Activity</h3>

            <p>
                Monitor registered Windows endpoints with a secure local agent for heartbeat and process telemetry.
            </p>

        </div>

    </div>

</section>


<!-- ================= HOW IT WORKS ================= -->

<section class="section how-section" id="how-it-works">

    <div class="section-heading">

        <span class="section-label">PROCESS</span>

        <h2>
            How It <span>Works</span>
        </h2>

        <p>
            MalwareGuard simplifies the file analysis process
            into three easy steps.
        </p>

    </div>


    <div class="steps-container">

        <div class="step">

            <div class="step-number">01</div>

            <div class="step-icon">
                <i class="fa-solid fa-cloud-arrow-up"></i>
            </div>

            <h3>Upload</h3>

            <p>
                Upload the file you want to check for potential threats.
            </p>

        </div>


        <div class="step-line"></div>


        <div class="step">

            <div class="step-number">02</div>

            <div class="step-icon">
                <i class="fa-solid fa-magnifying-glass-chart"></i>
            </div>

            <h3>Analyze</h3>

            <p>
                The system analyzes the file for suspicious characteristics.
            </p>

        </div>


        <div class="step-line"></div>


        <div class="step">

            <div class="step-number">03</div>

            <div class="step-icon">
                <i class="fa-solid fa-circle-check"></i>
            </div>

            <h3>Get Results</h3>

            <p>
                View the security classification and analysis results.
            </p>

        </div>

    </div>

</section>


<!-- ================= SCANNER PREVIEW ================= -->

<section class="scanner-section">

    <div class="section-heading">

        <span class="section-label">SCANNER PREVIEW</span>

        <h2>
            Secure File <span>Analysis</span>
        </h2>

        <p>
            Preview of the MalwareGuard scanning interface.
        </p>

    </div>


    <div class="scanner-container">

        <!-- DROP AREA -->

        <div class="drop-zone" id="dropZone">

            <div class="upload-icon">
                <i class="fa-solid fa-cloud-arrow-up"></i>
            </div>

            <h3>DROP YOUR FILE HERE</h3>

            <p>or click to browse files</p>

            <span>
                Maximum file size: 50 MB
            </span>

            <input type="file" id="fileInput" hidden>

            <button onclick="document.getElementById('fileInput').click()">
                Choose File
            </button>

        </div>


        <!-- RESULT -->

        <div class="result-card">

            <div class="result-header">

                <span>
                    <i class="fa-solid fa-file-shield"></i>
                    FILE ANALYSIS RESULT
                </span>

                <span class="completed">
                    COMPLETED
                </span>

            </div>


            <div class="file-name">

                <i class="fa-solid fa-file-zipper"></i>

                <div>
                    <strong>exam-project.zip</strong>
                    <small>ZIP Archive</small>
                </div>

            </div>


            <div class="safe-result">

                <div class="safe-icon">
                    <i class="fa-solid fa-check"></i>
                </div>

                <div>
                    <strong>SAFE</strong>
                    <span>No immediate threat detected</span>
                </div>

            </div>


            <div class="security-score">

                <div class="score-top">
                    <span>SECURITY SCORE</span>
                    <strong>96%</strong>
                </div>

                <div class="progress">
                    <div class="progress-bar"></div>
                </div>

            </div>


            <div class="result-details">

                <div>
                    <span>Threat Level</span>
                    <strong>Low</strong>
                </div>

                <div>
                    <span>Analysis Status</span>
                    <strong>Completed</strong>
                </div>

                <div>
                    <span>Detection</span>
                    <strong>No Threat Detected</strong>
                </div>

            </div>

        </div>

    </div>

</section>


<!-- ================= ABOUT ================= -->

<section class="section about-section" id="about">

    <div class="about-content">

        <div>

            <span class="section-label">ABOUT MALWAREGUARD</span>

            <h2>
                Smarter Protection
                <span>Starts Here.</span>
            </h2>

            <p>
                MalwareGuard is designed to provide a simple and
                understandable approach to malicious software detection.
                It helps users analyze files and understand possible
                security risks through clear results and security scores.
            </p>

            <p>
                The system focuses on making cybersecurity analysis
                easier to understand while providing users with
                useful information about their uploaded files.
            </p>

        </div>


        <div class="about-card">

            <i class="fa-solid fa-shield-heart"></i>

            <h3>Security First</h3>

            <p>
                Designed with a focus on security, clarity,
                and user-friendly threat analysis.
            </p>

        </div>

    </div>

</section>


<!-- ================= CTA ================= -->

<section class="cta-section">

    <div class="cta-glow"></div>

    <i class="fa-solid fa-shield-halved cta-shield"></i>

    <h2>
        Ready to Protect Your Files?
    </h2>

    <p>
        Start using MalwareGuard for intelligent file security analysis.
    </p>

    <a href="login.html" class="primary-btn">
        <i class="fa-solid fa-shield-virus"></i>
        Start Scanning
    </a>

</section>


<!-- ================= FOOTER ================= -->

<footer>

    <div class="footer-logo">
        <i class="fa-solid fa-shield-halved"></i>
        MalwareGuard
    </div>

    <p>
        An Intelligent Malicious Software Detection System
    </p>

    <div class="footer-line"></div>

    <small>
        © 2026 MalwareGuard. All rights reserved.
    </small>

</footer>


<script src="assets/js/script.js"></script>

</body>
</html>