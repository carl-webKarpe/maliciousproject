<?php
// File analysis shared by browser uploads (upload.php) and agent scans
// (api/agent.php). Two evidence sources are combined:
//
//   1. Static rules run locally on the file (filename, type and content
//      indicators). Each matched rule adds risk points.
//   2. VirusTotal hash reputation (optional). Only the SHA-256 hash is sent;
//      file contents are never uploaded to VirusTotal.
//
// Classification rules
//   critical  static points >= 70, or VirusTotal malicious >= 3
//   high      static points >= 45, or VirusTotal malicious 1-2
//   medium    static points >= 20, or VirusTotal suspicious > 0 (no malicious)
//   low       static points 1-19
//   safe      no static indicator and no VirusTotal detection; this means only
//             "nothing found by the checks that ran", never a guarantee
//   unknown   the file could not be analysed, so there is no evidence either way
// The stronger of the two sources wins.
//
// security_score is 100 minus the static and reputation risk points (floored
// at 0). It is a rule-based score, not a probability or a confidence level.

require_once __DIR__ . DIRECTORY_SEPARATOR . "bootstrap.php";

const MG_THREAT_ORDER = ["unknown" => -1, "safe" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4];

const MG_RECOMMENDED_ACTIONS = [
    "critical" => "Do not open or run this file. If it was already run, disconnect the device from the network and have an administrator investigate. MalwareGuard never deletes files automatically.",
    "high" => "Do not open the file. Verify where it came from and analyse it in an isolated sandbox before any use.",
    "medium" => "Review the findings and confirm the file's origin before opening it.",
    "low" => "Only low-risk indicators were found. Confirm the source if the file was unexpected.",
    "safe" => "No action required. No scanner can guarantee a file is clean, so stay cautious with unexpected files.",
    "unknown" => "No verdict could be reached. Re-scan later or analyse the file manually.",
];

function mg_scan_file(string $path, string $originalName): array
{
    $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    $size = @filesize($path);

    if (!is_file($path) || !is_readable($path) || $size === false) {
        return mg_unknown_scan_result($originalName, $extension, "The file could not be read for analysis.");
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = (string) ($finfo->file($path) ?: "application/octet-stream");
    $fileHash = (string) hash_file("sha256", $path);

    $analysis = analyzeFile($path, $originalName, $extension, $mimeType);
    $virusTotal = mg_vt_lookup($fileHash);
    $analysis = mergeVirusTotalResult($analysis, $virusTotal);

    $sources = ["MalwareGuard static rules"];
    if ($virusTotal["status"] === "found") {
        $sources[] = "VirusTotal hash reputation" . (!empty($virusTotal["cached"]) ? " (cached)" : "");
    }

    return $analysis + [
        "file_hash" => $fileHash,
        "file_type" => $mimeType,
        "file_extension" => $extension,
        "file_size" => (int) $size,
        "vt" => $virusTotal,
        "detection_ratio" => $virusTotal["status"] === "found"
            ? $virusTotal["malicious"] . "/" . $virusTotal["engines"]
            : null,
        "detection_source" => implode(", ", $sources),
        "recommended_action" => MG_RECOMMENDED_ACTIONS[$analysis["threat_level"]] ?? MG_RECOMMENDED_ACTIONS["unknown"],
        "error_message" => null,
    ];
}

function mg_unknown_scan_result(string $originalName, string $extension, string $error): array
{
    return [
        "threat_level" => "unknown",
        "detection_status" => "unknown",
        "security_score" => 0,
        "analysis_result" => $error,
        "findings" => [],
        "file_hash" => str_repeat("0", 64),
        "file_type" => null,
        "file_extension" => $extension,
        "file_size" => 0,
        "vt" => ["status" => "not_checked"],
        "detection_ratio" => null,
        "detection_source" => "None (analysis failed)",
        "recommended_action" => MG_RECOMMENDED_ACTIONS["unknown"],
        "error_message" => $error,
    ];
}

function mg_threat_from_points(int $riskPoints): array
{
    if ($riskPoints >= 70) {
        return ["critical", "malicious"];
    }
    if ($riskPoints >= 45) {
        return ["high", "suspicious"];
    }
    if ($riskPoints >= 20) {
        return ["medium", "suspicious"];
    }
    if ($riskPoints > 0) {
        return ["low", "suspicious"];
    }
    return ["safe", "safe"];
}

/*
|--------------------------------------------------------------------------
| STATIC FILE ANALYSIS FUNCTION
|--------------------------------------------------------------------------
*/

function analyzeFile($path, $filename, $extension, $mimeType)
{
    $findings = [];
    $riskPoints = 0;

    $addFinding = static function (string $type, string $name, string $severity, string $description, string $evidence, int $score) use (&$findings, &$riskPoints): void {
        $findings[] = [
            "type" => $type,
            "name" => $name,
            "severity" => $severity,
            "description" => $description,
            "evidence" => $evidence,
            "score" => $score,
        ];
        $riskPoints += $score;
    };

    // Suspicious filename patterns
    $filenamePatterns = ["/crack/i", "/keygen/i", "/payload/i", "/backdoor/i", "/trojan/i", "/ransom/i", "/stealer/i", "/loader/i", "/dropper/i"];
    foreach ($filenamePatterns as $pattern) {
        if (preg_match($pattern, $filename)) {
            $addFinding("filename_analysis", "Suspicious filename pattern", "medium", "The filename matches a configured suspicious pattern.", $filename, 20);
            break;
        }
    }

    // Double extension
    if (preg_match("/\.(jpg|jpeg|png|pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|bat|cmd|com|js|vbs|ps1|hta)$/i", $filename)) {
        $addFinding("filename_analysis", "Double extension detected", "high", "The filename contains a potentially deceptive double extension.", $filename, 35);
    }

    // Script files
    $scriptExtensions = ["js", "vbs", "ps1", "bat", "cmd", "hta"];
    if (in_array($extension, $scriptExtensions, true)) {
        $addFinding("file_type", "Script file", "low", "This file type can contain executable scripting instructions.", "." . $extension, 10);
    }

    // Executable files
    $executableExtensions = ["exe", "dll", "scr", "com", "msi", "sys", "cpl"];
    if (in_array($extension, $executableExtensions, true)) {
        $addFinding("file_type", "Executable file", "medium", "The file is an executable format and requires additional scrutiny.", "." . $extension, 15);
    }

    // Suspicious strings: inspect at most the first 2 MB.
    $content = file_get_contents($path, false, null, 0, 2 * 1024 * 1024);

    if ($content !== false) {
        // A Windows PE file ("MZ" header) disguised with a non-executable extension.
        if (strncmp($content, "MZ", 2) === 0 && !in_array($extension, $executableExtensions, true)) {
            $addFinding(
                "content_analysis",
                "Executable content with misleading extension",
                "high",
                "The file starts with a Windows executable (PE) header, but its extension does not indicate an executable.",
                "MZ header, ." . ($extension === "" ? "(none)" : $extension),
                45
            );
        }

        $patterns = [
            "powershell" => ["severity" => "medium", "score" => 20],
            "cmd.exe" => ["severity" => "medium", "score" => 15],
            "wscript.shell" => ["severity" => "medium", "score" => 20],
            "createobject" => ["severity" => "low", "score" => 10],
        ];
        foreach ($patterns as $pattern => $data) {
            if (stripos($content, $pattern) !== false) {
                $addFinding("content_analysis", "Suspicious command or script reference", $data["severity"], "A configured suspicious string was found in the file content.", $pattern, $data["score"]);
            }
        }
    }

    $riskPoints = min(100, $riskPoints);
    [$threatLevel, $status] = mg_threat_from_points($riskPoints);

    $result = $status === "safe"
        ? "No suspicious indicators were detected by the configured static analysis rules."
        : count($findings) . " security indicator(s) were detected by the configured static analysis rules.";

    return [
        "threat_level" => $threatLevel,
        "detection_status" => $status,
        "security_score" => max(0, 100 - $riskPoints),
        "analysis_result" => $result,
        "findings" => $findings,
    ];
}

/*
|--------------------------------------------------------------------------
| VirusTotal hash reputation
|--------------------------------------------------------------------------
|
| Results are cached in vt_cache (VT_CACHE_HOURS, default 24) and lookups are
| limited to VT_REQUESTS_PER_MINUTE (default 4) and VT_REQUESTS_PER_DAY
| (default 500), matching the public API's free quota.
|
*/

function mg_vt_lookup(string $fileHash): array
{
    $apiKey = malwareGuardSetting("VIRUSTOTAL_API_KEY");
    if ($apiKey === "" || !function_exists("curl_init")) {
        return [
            "status" => "not_configured",
            "message" => "VirusTotal reputation checks are not enabled. Add VIRUSTOTAL_API_KEY to .env to enable hash lookup.",
        ];
    }
    if (!preg_match('/^[a-f0-9]{64}$/', $fileHash)) {
        return ["status" => "unavailable", "message" => "Invalid file hash."];
    }

    $pdo = null;
    try {
        $pdo = mg_pdo();
        $cacheHours = mg_setting_int("VT_CACHE_HOURS", 24, 0, 24 * 30);
        $cached = $pdo->prepare(
            "SELECT status, malicious, suspicious, engines FROM vt_cache
             WHERE sha256 = ?
               AND fetched_at >= DATE_SUB(NOW(), INTERVAL IF(status = 'found', ?, 1) HOUR)"
        );
        $cached->execute([$fileHash, $cacheHours]);
        if ($row = $cached->fetch()) {
            return $row["status"] === "found"
                ? ["status" => "found", "malicious" => (int) $row["malicious"], "suspicious" => (int) $row["suspicious"], "engines" => (int) $row["engines"], "cached" => true]
                : ["status" => "not_found", "cached" => true, "message" => "VirusTotal has no record of this file hash."];
        }

        if (
            !mg_rate_limit("vt:minute", mg_setting_int("VT_REQUESTS_PER_MINUTE", 4, 1, 1000), 60) ||
            !mg_rate_limit("vt:day", mg_setting_int("VT_REQUESTS_PER_DAY", 500, 1, 1000000), 86400)
        ) {
            return ["status" => "rate_limited", "message" => "The VirusTotal lookup quota is used up for now; the hash was not checked. Re-scan later."];
        }
    } catch (Throwable $e) {
        // Without the cache tables the lookup still works, just uncached.
        error_log("VirusTotal cache unavailable: " . $e->getMessage());
        $pdo = null;
    }

    $curl = curl_init("https://www.virustotal.com/api/v3/files/" . rawurlencode($fileHash));
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ["x-apikey: " . $apiKey, "Accept: application/json"],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    $response = curl_exec($curl);
    $httpStatus = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $curlError = curl_error($curl);
    curl_close($curl);

    if (!is_string($response) || $httpStatus === 0) {
        return ["status" => "unavailable", "message" => "VirusTotal could not be reached" . ($curlError !== "" ? " ({$curlError})" : "") . "."];
    }
    if ($httpStatus === 404) {
        mg_vt_cache_store($pdo, $fileHash, "not_found", 0, 0, 0);
        return ["status" => "not_found", "message" => "VirusTotal has no record of this file hash."];
    }
    if ($httpStatus === 429) {
        return ["status" => "rate_limited", "message" => "VirusTotal rejected the lookup because the API quota was exceeded. Re-scan later."];
    }
    if ($httpStatus === 401 || $httpStatus === 403) {
        return ["status" => "auth_error", "message" => "VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY in .env."];
    }
    if ($httpStatus !== 200) {
        return ["status" => "unavailable", "message" => "VirusTotal returned HTTP {$httpStatus}."];
    }

    $payload = json_decode($response, true);
    $stats = $payload["data"]["attributes"]["last_analysis_stats"] ?? null;
    if (!is_array($stats)) {
        return ["status" => "unavailable", "message" => "VirusTotal returned an unexpected response."];
    }

    $malicious = max(0, (int) ($stats["malicious"] ?? 0));
    $suspicious = max(0, (int) ($stats["suspicious"] ?? 0));
    $engines = max(0, (int) array_sum(array_map("intval", $stats)));
    mg_vt_cache_store($pdo, $fileHash, "found", $malicious, $suspicious, $engines);

    return ["status" => "found", "malicious" => $malicious, "suspicious" => $suspicious, "engines" => $engines];
}

function mg_vt_cache_store(?PDO $pdo, string $hash, string $status, int $malicious, int $suspicious, int $engines): void
{
    if ($pdo === null) {
        return;
    }
    try {
        $pdo->prepare(
            "INSERT INTO vt_cache (sha256, status, malicious, suspicious, engines, fetched_at)
             VALUES (?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE status = VALUES(status), malicious = VALUES(malicious),
                 suspicious = VALUES(suspicious), engines = VALUES(engines), fetched_at = NOW()"
        )->execute([$hash, $status, $malicious, $suspicious, $engines]);
    } catch (Throwable $e) {
        error_log("VirusTotal cache write failed: " . $e->getMessage());
    }
}

function mergeVirusTotalResult(array $analysis, array $virusTotalResult): array
{
    $status = $virusTotalResult["status"] ?? "unavailable";

    if ($status !== "found") {
        $message = $virusTotalResult["message"] ?? "VirusTotal reputation data was unavailable.";
        $analysis["analysis_result"] .= " " . $message . " The verdict is based on static rules only.";
        return $analysis;
    }

    $malicious = $virusTotalResult["malicious"];
    $suspicious = $virusTotalResult["suspicious"];
    $engines = $virusTotalResult["engines"];

    if ($malicious === 0 && $suspicious === 0) {
        $analysis["analysis_result"] .= " VirusTotal hash lookup reported 0/{$engines} engine detections; this does not guarantee the file is safe.";
        return $analysis;
    }

    if ($malicious >= 3) {
        [$vtLevel, $vtStatus, $severity] = ["critical", "malicious", "critical"];
    } elseif ($malicious > 0) {
        [$vtLevel, $vtStatus, $severity] = ["high", "suspicious", "high"];
    } else {
        [$vtLevel, $vtStatus, $severity] = ["medium", "suspicious", "medium"];
    }

    if (MG_THREAT_ORDER[$vtLevel] > MG_THREAT_ORDER[$analysis["threat_level"]]) {
        $analysis["threat_level"] = $vtLevel;
        $analysis["detection_status"] = $vtStatus;
    }

    $riskPoints = min(100, ($malicious * 25) + ($suspicious * 10));
    $analysis["security_score"] = min($analysis["security_score"], max(0, 100 - $riskPoints));
    $analysis["findings"][] = [
        "type" => "threat_intelligence",
        "name" => "VirusTotal hash reputation",
        "severity" => $severity,
        "description" => "VirusTotal reported {$malicious} malicious and {$suspicious} suspicious engine detections. Only the SHA-256 hash was queried; the file was not uploaded.",
        "evidence" => "{$malicious}/{$engines} malicious, {$suspicious} suspicious",
        "score" => $riskPoints,
    ];
    $analysis["analysis_result"] .= " VirusTotal hash lookup reported {$malicious}/{$engines} malicious and {$suspicious} suspicious detections.";

    return $analysis;
}

// Saves a completed analysis to scans + detection_results in one transaction
// and returns the new scan id. $meta keys: user_id, file_name (stored name),
// original_file_name, file_path, scan_source, device_id, scan_request_id,
// source_path.
function mg_store_scan(PDO $pdo, array $result, array $meta): int
{
    $vt = $result["vt"] ?? [];
    $vtFound = ($vt["status"] ?? "") === "found";

    $pdo->beginTransaction();
    try {
        $pdo->prepare(
            "INSERT INTO scans
                (user_id, file_name, original_file_name, file_path, file_size, file_type, file_extension, file_hash,
                 threat_level, detection_status, security_score, detection_count, analysis_result, scan_engine, scanned_at,
                 scan_source, device_id, scan_request_id, source_path, vt_status, vt_malicious, vt_suspicious, vt_engines,
                 detection_source, recommended_action, error_message)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'MalwareGuard Engine', NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )->execute([
            (int) $meta["user_id"],
            substr((string) $meta["file_name"], 0, 255),
            substr((string) $meta["original_file_name"], 0, 255),
            substr((string) $meta["file_path"], 0, 255),
            (int) $result["file_size"],
            $result["file_type"] === null ? null : substr((string) $result["file_type"], 0, 255),
            substr((string) $result["file_extension"], 0, 64),
            $result["file_hash"],
            $result["threat_level"],
            $result["detection_status"],
            (int) $result["security_score"],
            count($result["findings"]),
            $result["analysis_result"],
            $meta["scan_source"] ?? "upload",
            $meta["device_id"] ?? null,
            $meta["scan_request_id"] ?? null,
            isset($meta["source_path"]) ? substr((string) $meta["source_path"], 0, 1024) : null,
            substr((string) ($vt["status"] ?? "not_checked"), 0, 32),
            $vtFound ? (int) $vt["malicious"] : null,
            $vtFound ? (int) $vt["suspicious"] : null,
            $vtFound ? (int) $vt["engines"] : null,
            $result["detection_source"],
            $result["recommended_action"],
            $result["error_message"],
        ]);
        $scanId = (int) $pdo->lastInsertId();

        $finding = $pdo->prepare(
            "INSERT INTO detection_results (scan_id, detection_type, detection_name, severity, description, evidence, score)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        foreach ($result["findings"] as $item) {
            $finding->execute([$scanId, $item["type"], $item["name"], $item["severity"], $item["description"], $item["evidence"], (int) $item["score"]]);
        }

        $pdo->commit();
        return $scanId;
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}
