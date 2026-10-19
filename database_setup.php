<?php
if (PHP_SAPI !== "cli") {
    http_response_code(403);
    echo "This script must be run from the command line. Use: php database_setup.php\n";
    exit(1);
}

require_once __DIR__ . DIRECTORY_SEPARATOR . "db.php";

$conn->close();

echo "Database schema is ready.\n";
