<?php
// mysqli connection used by the original pages. Settings come from .env
// (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS). The schema is created and
// upgraded by `php database_setup.php`, not on every request.

require_once __DIR__ . DIRECTORY_SEPARATOR . "app_config.php";

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    $conn = new mysqli(
        malwareGuardSetting("DB_HOST", "localhost"),
        malwareGuardSetting("DB_USER", "root"),
        malwareGuardSetting("DB_PASS", ""),
        malwareGuardSetting("DB_NAME", "malwareguard"),
        (int) malwareGuardSetting("DB_PORT", "3306")
    );
    $conn->set_charset("utf8mb4");
} catch (mysqli_sql_exception $e) {
    error_log("Database connection failed: " . $e->getMessage());
    if (PHP_SAPI === "cli") {
        fwrite(STDERR, "Database connection failed: " . $e->getMessage() . PHP_EOL);
        exit(1);
    }
    http_response_code(503);
    exit("The database is unavailable. Check that the MySQL Server service is running and that DB_* settings in .env are correct.");
}
