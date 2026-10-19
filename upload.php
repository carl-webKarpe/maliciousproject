<?php

session_start();

require_once "db.php";
require_once __DIR__ . DIRECTORY_SEPARATOR . "app_config.php";


/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
*/

if (
    !isset($_SESSION["logged_in"]) ||
    $_SESSION["logged_in"] !== true
) {
    header("Location: login.html");
    exit;
}


/*
|--------------------------------------------------------------------------
| Request validation
|--------------------------------------------------------------------------
*/

if ($_SERVER["REQUEST_METHOD"] !== "POST") {

    header("Location: scan.php");

    exit;
}


if (!isset($_FILES["scan_file"])) {

    die("No file was uploaded.");

}


$file = $_FILES["scan_file"];


/*
|--------------------------------------------------------------------------
| Upload error
|--------------------------------------------------------------------------
*/

if ($file["error"] !== UPLOAD_ERR_OK) {

    die(
        "File upload failed. Error code: " .
        $file["error"]
    );

}


/*
|--------------------------------------------------------------------------
| File size
|--------------------------------------------------------------------------
|
| 50 MB maximum
|
*/

$maxSize = 50 * 1024 * 1024;

if ($file["size"] > $maxSize) {

    die("File is larger than the 50 MB limit.");

}


if ($file["size"] <= 0) {

    die("The uploaded file is empty.");

}


/*
|--------------------------------------------------------------------------
| Original filename
|--------------------------------------------------------------------------
*/

$originalName =
    basename($file["name"]);


/*
|--------------------------------------------------------------------------
| Extension
|--------------------------------------------------------------------------
*/

$extension =
    strtolower(
        pathinfo(
            $originalName,
            PATHINFO_EXTENSION
        )
    );


/*
|--------------------------------------------------------------------------
| Block dangerous executable upload types
|--------------------------------------------------------------------------
|
| These can still be analyzed as files, but we don't
| allow them to become executable web content.
|
*/

$blockedWebExtensions = [
    "php",
    "php3",
    "php4",
    "php5",
    "phtml",
    "phar",
    "cgi",
    "pl",
    "asp",
    "aspx",
    "jsp",
    "sh"
];


/*
|--------------------------------------------------------------------------
| MIME type
|--------------------------------------------------------------------------
*/

$finfo = new finfo(FILEINFO_MIME_TYPE);

$mimeType =
    $finfo->file(
        $file["tmp_name"]
    );


/*
|--------------------------------------------------------------------------
| SHA-256
|--------------------------------------------------------------------------
*/

$fileHash =
    hash_file(
        "sha256",
        $file["tmp_name"]
    );


/*
|--------------------------------------------------------------------------
| Generate safe server filename
|--------------------------------------------------------------------------
*/

// Stored under a random name with a neutral extension, so an uploaded
// .php/.phtml/.exe can never be executed by the web server.
$serverFileName = bin2hex(random_bytes(16)) . ".quarantine";


/*
|--------------------------------------------------------------------------
| Upload directory
|--------------------------------------------------------------------------
*/

$uploadDirectory =
    dirname(__DIR__) .
    DIRECTORY_SEPARATOR .
    "uploads";


if (!is_dir($uploadDirectory)) {

    mkdir(
        $uploadDirectory,
        0750,
        true
    );

}

// Belt and braces: deny any direct web access to the upload folder (Apache).
$htaccess = $uploadDirectory . DIRECTORY_SEPARATOR . ".htaccess";
if (!file_exists($htaccess)) {
    file_put_contents(
        $htaccess,
        "Require all denied\nphp_flag engine off\nOptions -ExecCGI\nRemoveHandler .php .phtml .phar\n"
    );
}


/*
|--------------------------------------------------------------------------
| Analyze file
|--------------------------------------------------------------------------
*/

$analysis =
    analyzeFile(
        $file["tmp_name"],
        $originalName,
        $extension,
        $mimeType
    );

$virusTotalResult = lookupVirusTotalHash($fileHash);
if ($virusTotalResult["status"] === "found") {
    $analysis = mergeVirusTotalResult($analysis, $virusTotalResult);
}


/*
|--------------------------------------------------------------------------
| Determine final classification
|--------------------------------------------------------------------------
*/

$threatLevel =
    $analysis["threat_level"];

$detectionStatus =
    $analysis["detection_status"];

$securityScore =
    $analysis["security_score"];

$detectionCount =
    count($analysis["findings"]);

$analysisResult =
    $analysis["analysis_result"];


/*
|--------------------------------------------------------------------------
| Save uploaded file
|--------------------------------------------------------------------------
*/

$destination =
    $uploadDirectory .
    DIRECTORY_SEPARATOR .
    $serverFileName;


if (!move_uploaded_file(
    $file["tmp_name"],
    $destination
)) {

    die("Unable to save uploaded file.");

}

chmod($destination, 0600);


/*
|--------------------------------------------------------------------------
| Database path
|--------------------------------------------------------------------------
*/

$filePath =
    "uploads/" .
    $serverFileName;


/*
|--------------------------------------------------------------------------
| Insert scan
|--------------------------------------------------------------------------
*/

$userId =
    $_SESSION["user_id"];


$stmt = $conn->prepare(
    "INSERT INTO scans
    (
        user_id,
        file_name,
        original_file_name,
        file_path,
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
        scanned_at
    )
    VALUES
    (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'MalwareGuard Engine', NOW()
    )"
);


$stmt->bind_param(
    "isssisssssdis",
    $userId,
    $serverFileName,
    $originalName,
    $filePath,
    $file["size"],
    $mimeType,
    $extension,
    $fileHash,
    $threatLevel,
    $detectionStatus,
    $securityScore,
    $detectionCount,
    $analysisResult
);


if (!$stmt->execute()) {

    if (file_exists($destination)) {
        unlink($destination);
    }

    die(
        "Database error: " .
        $stmt->error
    );

}


$scanId =
    $stmt->insert_id;

$stmt->close();


/*
|--------------------------------------------------------------------------
| Insert detection findings
|--------------------------------------------------------------------------
*/

if (!empty($analysis["findings"])) {

    $findingStmt = $conn->prepare(
        "INSERT INTO detection_results
        (
            scan_id,
            detection_type,
            detection_name,
            severity,
            description,
            evidence,
            score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)"
    );


    foreach ($analysis["findings"] as $finding) {

        $type =
            $finding["type"];

        $name =
            $finding["name"];

        $severity =
            $finding["severity"];

        $description =
            $finding["description"];

        $evidence =
            $finding["evidence"];

        $score =
            $finding["score"];


        $findingStmt->bind_param(
            "isssssd",
            $scanId,
            $type,
            $name,
            $severity,
            $description,
            $evidence,
            $score
        );


        $findingStmt->execute();

    }


    $findingStmt->close();

}


$conn->close();


/*
|--------------------------------------------------------------------------
| Redirect to result
|--------------------------------------------------------------------------
*/

if (in_array($_SESSION["user_role"] ?? "", ["admin", "super_admin"], true)) {
    header("Location: admin/dashboard.php?scan_id=" . urlencode((string) $scanId) . "#scan-result");
} else {
    header(
        "Location: results.php?id=" .
        urlencode($scanId)
    );
}

exit;


/*
|--------------------------------------------------------------------------
| STATIC FILE ANALYSIS FUNCTION
|--------------------------------------------------------------------------
*/

function analyzeFile(
    $path,
    $filename,
    $extension,
    $mimeType
) {

    $findings = [];

    $riskPoints = 0;


    /*
    |--------------------------------------------------------------------------
    | Suspicious filename patterns
    |--------------------------------------------------------------------------
    */

    $filenamePatterns = [
        "/crack/i",
        "/keygen/i",
        "/payload/i",
        "/backdoor/i",
        "/trojan/i",
        "/ransom/i",
        "/stealer/i",
        "/loader/i",
        "/dropper/i"
    ];


    foreach ($filenamePatterns as $pattern) {

        if (preg_match(
            $pattern,
            $filename
        )) {

            $findings[] = [

                "type" =>
                    "filename_analysis",

                "name" =>
                    "Suspicious filename pattern",

                "severity" =>
                    "medium",

                "description" =>
                    "The filename matches a configured suspicious pattern.",

                "evidence" =>
                    $filename,

                "score" =>
                    20

            ];

            $riskPoints += 20;

            break;

        }

    }


    /*
    |--------------------------------------------------------------------------
    | Double extension
    |--------------------------------------------------------------------------
    */

    if (
        preg_match(
            "/\.(jpg|jpeg|png|pdf|doc|txt)\.(exe|scr|bat|cmd|com)$/i",
            $filename
        )
    ) {

        $findings[] = [

            "type" =>
                "filename_analysis",

            "name" =>
                "Double extension detected",

            "severity" =>
                "high",

            "description" =>
                "The filename contains a potentially deceptive double extension.",

            "evidence" =>
                $filename,

            "score" =>
                35

        ];

        $riskPoints += 35;

    }


    /*
    |--------------------------------------------------------------------------
    | Script files
    |--------------------------------------------------------------------------
    */

    $scriptExtensions = [
        "js",
        "vbs",
        "ps1",
        "bat",
        "cmd",
        "hta"
    ];


    if (
        in_array(
            $extension,
            $scriptExtensions,
            true
        )
    ) {

        $findings[] = [

            "type" =>
                "file_type",

            "name" =>
                "Script file",

            "severity" =>
                "low",

            "description" =>
                "This file type can contain executable scripting instructions.",

            "evidence" =>
                "." . $extension,

            "score" =>
                10

        ];

        $riskPoints += 10;

    }


    /*
    |--------------------------------------------------------------------------
    | Executable files
    |--------------------------------------------------------------------------
    */

    $executableExtensions = [
        "exe",
        "dll",
        "scr",
        "com",
        "msi"
    ];


    if (
        in_array(
            $extension,
            $executableExtensions,
            true
        )
    ) {

        $findings[] = [

            "type" =>
                "file_type",

            "name" =>
                "Executable file",

            "severity" =>
                "medium",

            "description" =>
                "The uploaded file is an executable format and requires additional scrutiny.",

            "evidence" =>
                "." . $extension,

            "score" =>
                15

        ];

        $riskPoints += 15;

    }


    /*
    |--------------------------------------------------------------------------
    | Suspicious strings
    |--------------------------------------------------------------------------
    |
    | We inspect a limited amount of content.
    |
    */

    $content =
        file_get_contents(
            $path,
            false,
            null,
            0,
            2 * 1024 * 1024
        );


    if ($content !== false) {

        $patterns = [

            "powershell" => [
                "severity" => "medium",
                "score" => 20
            ],

            "cmd.exe" => [
                "severity" => "medium",
                "score" => 15
            ],

            "wscript.shell" => [
                "severity" => "medium",
                "score" => 20
            ],

            "createobject" => [
                "severity" => "low",
                "score" => 10
            ]

        ];


        foreach ($patterns as $pattern => $data) {

            if (
                stripos(
                    $content,
                    $pattern
                ) !== false
            ) {

                $findings[] = [

                    "type" =>
                        "content_analysis",

                    "name" =>
                        "Suspicious command or script reference",

                    "severity" =>
                        $data["severity"],

                    "description" =>
                        "A configured suspicious string was found in the file content.",

                    "evidence" =>
                        $pattern,

                    "score" =>
                        $data["score"]

                ];

                $riskPoints +=
                    $data["score"];

            }

        }

    }


    /*
    |--------------------------------------------------------------------------
    | Limit risk score
    |--------------------------------------------------------------------------
    */

    if ($riskPoints > 100) {
        $riskPoints = 100;
    }


    /*
    |--------------------------------------------------------------------------
    | Security score
    |--------------------------------------------------------------------------
    */

    $securityScore =
        max(
            0,
            100 - $riskPoints
        );


    /*
    |--------------------------------------------------------------------------
    | Classification
    |--------------------------------------------------------------------------
    */

    if ($riskPoints >= 70) {

        $threatLevel = "critical";

        $status = "malicious";

    }

    elseif ($riskPoints >= 45) {

        $threatLevel = "high";

        $status = "suspicious";

    }

    elseif ($riskPoints >= 20) {

        $threatLevel = "medium";

        $status = "suspicious";

    }

    elseif ($riskPoints > 0) {

        $threatLevel = "low";

        $status = "suspicious";

    }

    else {

        $threatLevel = "safe";

        $status = "safe";

    }


    /*
    |--------------------------------------------------------------------------
    | Result message
    |--------------------------------------------------------------------------
    */

    if ($status === "safe") {

        $result =
            "No suspicious indicators were detected by the configured static analysis rules.";

    }

    else {

        $result =
            count($findings) .
            " security indicator(s) were detected by the configured static analysis rules.";

    }


    return [

        "threat_level" =>
            $threatLevel,

        "detection_status" =>
            $status,

        "security_score" =>
            $securityScore,

        "analysis_result" =>
            $result,

        "findings" =>
            $findings

    ];

}


function lookupVirusTotalHash(string $fileHash): array
{
    $apiKey = malwareGuardSetting("VIRUSTOTAL_API_KEY");
    if ($apiKey === "" || !function_exists("curl_init")) {
        return [
            "status" => "not_configured",
            "message" => "VirusTotal reputation checks are not enabled. Add VIRUSTOTAL_API_KEY to .env to enable hash lookup."
        ];
    }

    $curl = curl_init("https://www.virustotal.com/api/v3/files/" . rawurlencode($fileHash));
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ["x-apikey: " . $apiKey, "Accept: application/json"],
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS
    ]);

    $response = curl_exec($curl);
    $httpStatus = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if (!is_string($response) || $httpStatus !== 200) {
        return ["status" => $httpStatus === 404 ? "not_found" : "unavailable"];
    }

    $payload = json_decode($response, true);
    $stats = $payload["data"]["attributes"]["last_analysis_stats"] ?? null;
    if (!is_array($stats)) {
        return ["status" => "unavailable"];
    }

    return [
        "status" => "found",
        "malicious" => max(0, (int) ($stats["malicious"] ?? 0)),
        "suspicious" => max(0, (int) ($stats["suspicious"] ?? 0)),
        "engines" => max(0, (int) array_sum($stats))
    ];
}


function mergeVirusTotalResult(array $analysis, array $virusTotalResult): array
{
    if (($virusTotalResult["status"] ?? "") === "not_configured") {
        $analysis["analysis_result"] .= " " . ($virusTotalResult["message"] ?? "VirusTotal reputation checks are not enabled.");
        return $analysis;
    }

    $malicious = $virusTotalResult["malicious"];
    $suspicious = $virusTotalResult["suspicious"];
    $engines = $virusTotalResult["engines"];

    if ($malicious === 0 && $suspicious === 0) {
        $analysis["analysis_result"] .= " VirusTotal hash lookup reported no malicious or suspicious detections across {$engines} engines; this does not guarantee the file is safe.";
        return $analysis;
    }

    $riskPoints = min(100, ($malicious * 25) + ($suspicious * 10));
    $analysis["security_score"] = min($analysis["security_score"], max(0, 100 - $riskPoints));
    $analysis["detection_count"] = count($analysis["findings"]) + 1;

    if ($malicious >= 3) {
        $analysis["threat_level"] = "critical";
        $analysis["detection_status"] = "malicious";
        $severity = "critical";
    } else {
        $analysis["threat_level"] = "high";
        $analysis["detection_status"] = "suspicious";
        $severity = $malicious > 0 ? "high" : "medium";
    }

    $analysis["findings"][] = [
        "type" => "threat_intelligence",
        "name" => "VirusTotal hash reputation",
        "severity" => $severity,
        "description" => "VirusTotal reported {$malicious} malicious and {$suspicious} suspicious engine detections. Only the SHA-256 hash was queried; the file was not uploaded.",
        "evidence" => "{$malicious} malicious, {$suspicious} suspicious, {$engines} total engines",
        "score" => $riskPoints
    ];
    $analysis["analysis_result"] .= " VirusTotal hash lookup reported {$malicious} malicious and {$suspicious} suspicious detections across {$engines} engines.";

    return $analysis;
}

?>
