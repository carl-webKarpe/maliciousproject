<?php
// Creates the database if needed, applies database/malwareguard.sql and every
// pending migration in database/migrations/. Safe to run repeatedly: it never
// drops tables or deletes data.
//
//   php database_setup.php           apply schema and pending migrations
//   php database_setup.php --check   only report status (exit 1 if pending)

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    echo "This script must be run from the command line. Use: php database_setup.php\n";
    exit(1);
}

require_once __DIR__ . DIRECTORY_SEPARATOR . "includes" . DIRECTORY_SEPARATOR . "bootstrap.php";

$checkOnly = in_array("--check", $argv, true);
$config = mg_db_config();

try {
    $server = new PDO(
        sprintf("mysql:host=%s;port=%d;charset=utf8mb4", $config["host"], $config["port"]),
        $config["user"],
        $config["pass"],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    fwrite(STDERR, "Cannot connect to MySQL at {$config["host"]}:{$config["port"]} as '{$config["user"]}'.\n");
    fwrite(STDERR, "Reason: " . $e->getMessage() . "\n");
    fwrite(STDERR, "Check that the MySQL Server Windows service is running and that DB_* values in .env are correct.\n");
    exit(1);
}

if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $config["name"])) {
    fwrite(STDERR, "DB_NAME may contain only letters, digits and underscores.\n");
    exit(1);
}

$exists = $server->prepare("SELECT 1 FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?");
$exists->execute([$config["name"]]);
if (!$exists->fetchColumn()) {
    if ($checkOnly) {
        echo "Database '{$config["name"]}' does not exist yet. Run: php database_setup.php\n";
        exit(1);
    }
    $server->exec("CREATE DATABASE `{$config["name"]}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "Created database '{$config["name"]}'.\n";
}
$server = null;

$pdo = mg_pdo();

// Splits a .sql file into statements. The files in database/ use plain
// semicolon-terminated statements (no DELIMITER blocks) so they also run
// unchanged in MySQL Workbench.
function mg_sql_statements(string $path): array
{
    $sql = (string) file_get_contents($path);
    $sql = preg_replace('/^\s*--.*$/m', '', $sql);
    $statements = [];
    foreach (explode(";", $sql) as $statement) {
        $statement = trim($statement);
        // The files name the default database for Workbench users; the runner
        // always uses DB_NAME from .env instead.
        if ($statement === "" || preg_match('/^(CREATE\s+DATABASE|USE)\s/i', $statement)) {
            continue;
        }
        $statements[] = $statement;
    }
    return $statements;
}

// MySQL error codes meaning "this change is already in place".
const MG_ALREADY_APPLIED = [1050, 1060, 1061, 1826];

function mg_apply_file(PDO $pdo, string $path): int
{
    $applied = 0;
    foreach (mg_sql_statements($path) as $statement) {
        try {
            $pdo->exec($statement);
            $applied++;
        } catch (PDOException $e) {
            $code = (int) ($e->errorInfo[1] ?? 0);
            if (!in_array($code, MG_ALREADY_APPLIED, true)) {
                throw new RuntimeException(basename($path) . ": " . $e->getMessage() . "\nStatement: " . substr($statement, 0, 300));
            }
        }
    }
    return $applied;
}

$migrationFiles = glob(__DIR__ . "/database/migrations/*.sql") ?: [];
sort($migrationFiles, SORT_STRING);

$hasMigrationTable = (bool) $pdo->query(
    "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'schema_migrations'"
)->fetchColumn();
$appliedVersions = $hasMigrationTable
    ? $pdo->query("SELECT version FROM schema_migrations")->fetchAll(PDO::FETCH_COLUMN)
    : [];
$pending = array_values(array_filter(
    $migrationFiles,
    static fn (string $file): bool => !in_array(basename($file, ".sql"), $appliedVersions, true)
));

if ($checkOnly) {
    if ($pending) {
        echo "Pending migrations: " . implode(", ", array_map("basename", $pending)) . "\n";
        exit(1);
    }
    echo "Database schema is up to date.\n";
    exit(0);
}

try {
    mg_apply_file($pdo, __DIR__ . "/database/malwareguard.sql");
    foreach ($pending as $file) {
        mg_apply_file($pdo, $file);
        $pdo->prepare("INSERT IGNORE INTO schema_migrations (version) VALUES (?)")->execute([basename($file, ".sql")]);
        echo "Applied migration " . basename($file) . ".\n";
    }
} catch (RuntimeException $e) {
    fwrite(STDERR, "Schema update failed: " . $e->getMessage() . "\n");
    exit(1);
}

echo "Database schema is ready.\n";
