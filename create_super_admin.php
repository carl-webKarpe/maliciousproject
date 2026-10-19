<?php
if (PHP_SAPI !== "cli") {
    http_response_code(403);
    echo "This script must be run from the command line. Use: php create_super_admin.php\n";
    exit(1);
}

require __DIR__ . DIRECTORY_SEPARATOR . "super_admin" . DIRECTORY_SEPARATOR . "create_account.php";