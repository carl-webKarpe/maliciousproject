<?php
// Router for PHP's built-in web server (php -S host:port router.php).
// The built-in server would otherwise serve every file in the project,
// including .env, so private paths are refused here.

$path = rawurldecode((string) parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH));
$path = "/" . ltrim(str_replace("\\", "/", $path), "/");

$deniedPrefixes = ["/.", "/vendor/", "/database/", "/includes/", "/runtime/", "/tools/", "/agent/", "/uploads/", "/node_modules/"];
$deniedFiles = [
    "/db.php", "/app_config.php", "/mail_config.php", "/database_setup.php", "/create_super_admin.php",
    "/rotate_admin_password.php", "/rotate_user_password.php", "/router.php", "/composer.json", "/composer.lock",
];

$isDenied = in_array(strtolower($path), $deniedFiles, true)
    || preg_match('#/\.#', $path)
    || preg_match('#\.(sql|md|bat|ps1|py|json|lock|log|env|example|ini|pm)$#i', $path);
foreach ($deniedPrefixes as $prefix) {
    if (stripos($path, $prefix) === 0) {
        $isDenied = true;
    }
}

if ($isDenied) {
    http_response_code(404);
    header("Content-Type: text/plain");
    echo "Not found.";
    return true;
}

if ($path === "/") {
    return false; // let the server pick index.php
}

$file = __DIR__ . $path;
if (is_file($file)) {
    return false; // serve the file (PHP scripts run, static files are sent)
}

http_response_code(404);
header("Content-Type: text/plain");
echo "Not found.";
return true;
