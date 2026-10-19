<?php

session_start();

require_once __DIR__ . DIRECTORY_SEPARATOR . "includes" . DIRECTORY_SEPARATOR . "scan_engine.php";


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

// A body larger than post_max_size arrives with empty $_FILES and $_POST.
if (empty($_FILES) && (int) ($_SERVER["CONTENT_LENGTH"] ?? 0) > 0) {
    http_response_code(413);
    die("The file is larger than the server's upload limit (50 MB).");
}

if (!isset($_FILES["scan_file"])) {
    die("No file was uploaded.");
}

$file = $_FILES["scan_file"];

if (!is_int($file["error"] ?? null)) {
    die("Upload one file at a time.");
}


/*
|--------------------------------------------------------------------------
| Upload error
|--------------------------------------------------------------------------
*/

if ($file["error"] !== UPLOAD_ERR_OK) {
    $uploadErrors = [
        UPLOAD_ERR_INI_SIZE => "The file is larger than the server's upload limit.",
        UPLOAD_ERR_FORM_SIZE => "The file is larger than the form allows.",
        UPLOAD_ERR_PARTIAL => "The file was only partially uploaded. Please try again.",
        UPLOAD_ERR_NO_FILE => "No file was uploaded.",
    ];
    die($uploadErrors[$file["error"]] ?? "File upload failed. Error code: " . $file["error"]);
}


/*
|--------------------------------------------------------------------------
| File size (50 MB maximum)
|--------------------------------------------------------------------------
*/

$maxSize = 50 * 1024 * 1024;

if ($file["size"] > $maxSize) {
    die("File is larger than the 50 MB limit.");
}

if ($file["size"] <= 0) {
    die("The uploaded file is empty.");
}

if (!mg_rate_limit("upload:user:" . (int) $_SESSION["user_id"], 30, 600)) {
    http_response_code(429);
    die("Too many scans in a short time. Wait a few minutes and try again.");
}

$originalName = basename((string) $file["name"]);


/*
|--------------------------------------------------------------------------
| Analyze file
|--------------------------------------------------------------------------
*/

$analysis = mg_scan_file($file["tmp_name"], $originalName);


/*
|--------------------------------------------------------------------------
| Save uploaded file to quarantine
|--------------------------------------------------------------------------
|
| Stored outside the project directory under a random name with a neutral
| extension, so an uploaded .php/.phtml/.exe can never be executed by the
| web server.
|
*/

$serverFileName = bin2hex(random_bytes(16)) . ".quarantine";
$uploadDirectory = dirname(__DIR__) . DIRECTORY_SEPARATOR . "uploads";

if (!is_dir($uploadDirectory) && !mkdir($uploadDirectory, 0750, true) && !is_dir($uploadDirectory)) {
    die("Unable to create the quarantine folder.");
}

// Belt and braces: deny any direct web access to the upload folder (Apache).
$htaccess = $uploadDirectory . DIRECTORY_SEPARATOR . ".htaccess";
if (!file_exists($htaccess)) {
    file_put_contents(
        $htaccess,
        "Require all denied\nphp_flag engine off\nOptions -ExecCGI\nRemoveHandler .php .phtml .phar\n"
    );
}

$destination = $uploadDirectory . DIRECTORY_SEPARATOR . $serverFileName;

if (!move_uploaded_file($file["tmp_name"], $destination)) {
    die("Unable to save uploaded file.");
}

chmod($destination, 0600);


/*
|--------------------------------------------------------------------------
| Insert scan and findings
|--------------------------------------------------------------------------
*/

try {
    $scanId = mg_store_scan(mg_pdo(), $analysis, [
        "user_id" => (int) $_SESSION["user_id"],
        "file_name" => $serverFileName,
        "original_file_name" => $originalName,
        "file_path" => "uploads/" . $serverFileName,
        "scan_source" => "upload",
    ]);
} catch (Throwable $e) {
    if (file_exists($destination)) {
        unlink($destination);
    }
    error_log("Saving scan failed: " . $e->getMessage());
    die("The scan finished but could not be saved. Check that `php database_setup.php` has been run.");
}

mg_audit("user", (string) $_SESSION["user_id"], "scan.upload", "scan:" . $scanId, [
    "file" => $originalName,
    "threat_level" => $analysis["threat_level"],
]);


/*
|--------------------------------------------------------------------------
| Redirect to result
|--------------------------------------------------------------------------
*/

if (in_array($_SESSION["user_role"] ?? "", ["admin", "super_admin"], true)) {
    header("Location: admin/dashboard.php?scan_id=" . urlencode((string) $scanId) . "#scan-result");
} else {
    header("Location: results.php?id=" . urlencode((string) $scanId));
}

exit;
