<?php
// Checks run by START_MALICIOUSPROJECT.bat before the server starts.
//   php tools/preflight.php              human-readable checks, exit 1 on failure
//   php tools/preflight.php --print-env  prints APP_HOST=... and APP_PORT=... for the batch file

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit;
}

$root = dirname(__DIR__);
$printEnv = in_array("--print-env", $argv, true);
$failures = 0;

function report(string $status, string $message): void
{
    global $printEnv;
    if (!$printEnv) {
        echo str_pad("[$status]", 7) . " $message" . PHP_EOL;
    }
}

if (!$printEnv) {
    if (PHP_VERSION_ID < 80100) {
        report("FAIL", "PHP " . PHP_VERSION . " is too old. Install PHP 8.1 or newer.");
        exit(1);
    }
    report("OK", "PHP " . PHP_VERSION . " (" . PHP_BINARY . ")");

    $iniFile = php_ini_loaded_file() ?: "(no php.ini loaded: copy php.ini-development to php.ini next to php.exe)";
    foreach (["pdo_mysql", "mysqli", "curl", "fileinfo", "openssl", "mbstring"] as $extension) {
        if (!extension_loaded($extension)) {
            report("FAIL", "PHP extension '$extension' is not enabled. In $iniFile remove the ';' before extension=$extension (and set extension_dir=\"ext\").");
            $failures++;
        }
    }
    if ($failures === 0) {
        report("OK", "Required PHP extensions are enabled");
    }

    if (!is_file("$root/vendor/autoload.php")) {
        report("FAIL", "Composer packages are missing. In the project folder run: composer install");
        $failures++;
    } else {
        report("OK", "Composer packages installed");
    }
}

if (!is_file("$root/.env")) {
    if (!$printEnv) {
        if (is_file("$root/.env.example") && copy("$root/.env.example", "$root/.env")) {
            report("FAIL", "No .env file existed, so one was created from .env.example. Edit .env (DB_USER, DB_PASS, ...) and start again.");
        } else {
            report("FAIL", "The .env configuration file is missing. Copy .env.example to .env and edit it.");
        }
    }
    exit(1);
}

require_once "$root/app_config.php";

$host = malwareGuardSetting("APP_HOST", "127.0.0.1");
$port = (int) malwareGuardSetting("APP_PORT", "8000");

if (!filter_var($host, FILTER_VALIDATE_IP)) {
    report("FAIL", "APP_HOST must be an IP address such as 127.0.0.1, 0.0.0.0 or this PC's LAN IP (got '$host').");
    exit(1);
}
if ($port < 1 || $port > 65535) {
    report("FAIL", "APP_PORT must be between 1 and 65535.");
    exit(1);
}

if ($printEnv) {
    echo "APP_HOST=$host" . PHP_EOL . "APP_PORT=$port" . PHP_EOL;
    exit(0);
}

$socket = @stream_socket_server("tcp://" . ($host === "0.0.0.0" ? "0.0.0.0" : $host) . ":$port", $errno, $errstr);
if ($socket === false) {
    report("FAIL", "Cannot listen on $host:$port ($errstr). Another program is using the port, or the address does not belong to this PC. Change APP_PORT/APP_HOST in .env, or run STOP_MALICIOUSPROJECT.bat if MalwareGuard is already running.");
    $failures++;
} else {
    fclose($socket);
    report("OK", "Port $port is free on $host");
}

if ($host === "0.0.0.0") {
    report("WARN", "APP_HOST=0.0.0.0 accepts connections on every network this PC is connected to. Prefer this PC's LAN IP if only one network should reach it.");
} elseif ($host === "127.0.0.1") {
    report("INFO", "APP_HOST=127.0.0.1: only this PC can connect. Set APP_HOST to this PC's LAN IP so agents on other computers can reach the server.");
}

require_once "$root/includes/bootstrap.php";
$db = mg_db_config();
try {
    new PDO(
        sprintf("mysql:host=%s;port=%d;charset=utf8mb4", $db["host"], $db["port"]),
        $db["user"],
        $db["pass"],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]
    );
    report("OK", "MySQL Server reachable at {$db["host"]}:{$db["port"]} as '{$db["user"]}'");
} catch (PDOException $e) {
    $message = $e->getMessage();
    if (str_contains($message, "2002") || stripos($message, "refused") !== false) {
        report("FAIL", "MySQL Server is not answering at {$db["host"]}:{$db["port"]}. Start the MySQL service (services.msc > MySQL80 > Start) and try again.");
    } elseif (str_contains($message, "1045")) {
        report("FAIL", "MySQL rejected user '{$db["user"]}'. Check DB_USER and DB_PASS in .env (see README: Create the database account).");
    } else {
        report("FAIL", "Cannot connect to MySQL: $message");
    }
    $failures++;
}

if (mg_setting_bool("AUTO_SCAN_NEW_FILES")) {
    report("INFO", "AUTO_SCAN_NEW_FILES=true: agents upload every new file in monitored folders to this server for scanning.");
}

exit($failures > 0 ? 1 : 0);
