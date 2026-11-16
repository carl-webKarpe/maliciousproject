<?php
// Builds maliciousproject_xampp.sql: a complete, brand-new MalwareGuard
// database that keeps this server's login accounts.
//
//   C:\xampp\php\php.exe tools\export_for_transfer.php
//   C:\xampp\php\php.exe tools\export_for_transfer.php D:\backup\maliciousproject_xampp.sql
//
// The file contains every table the system needs, all EMPTY (no file events,
// search activity, scans, computers or tokens), plus the current user, admin
// and super-admin accounts with their existing passwords. Import it on the new
// PC in phpMyAdmin (Import tab).
//
// The output holds password hashes: keep it private. Git ignores
// database/maliciousproject_xampp.sql, so it is never pushed by accident.

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit;
}

require_once dirname(__DIR__) . DIRECTORY_SEPARATOR . "includes" . DIRECTORY_SEPARATOR . "bootstrap.php";

$root = dirname(__DIR__);
$target = $argv[1] ?? $root . DIRECTORY_SEPARATOR . "database" . DIRECTORY_SEPARATOR . "maliciousproject_xampp.sql";

// Table definitions come from the maintained schema file, so the export always
// matches the current code, whatever state this server's database is in.
$schemaFile = $root . "/database/malwareguard_xampp.sql";
$schemaSql = file_get_contents($schemaFile);
if ($schemaSql === false) {
    fwrite(STDERR, "Cannot read $schemaFile\n");
    exit(1);
}
$from = strpos($schemaSql, "SET FOREIGN_KEY_CHECKS = 0;");
$to = strpos($schemaSql, "-- Marks the migrations");
if ($from === false || $to === false) {
    fwrite(STDERR, "Unexpected format in $schemaFile\n");
    exit(1);
}
$tables = trim(substr($schemaSql, $from + strlen("SET FOREIGN_KEY_CHECKS = 0;"), $to - $from - strlen("SET FOREIGN_KEY_CHECKS = 0;")));

$migrations = array_map(static fn (string $file): string => basename($file, ".sql"), glob($root . "/database/migrations/*.sql") ?: []);
sort($migrations, SORT_STRING);

try {
    $pdo = mg_pdo();
    $users = $pdo->query("SELECT name, email, password, role, status, created_at FROM users ORDER BY id")->fetchAll();
} catch (Throwable $e) {
    fwrite(STDERR, "Cannot read the accounts from the database: " . $e->getMessage() . "\n");
    fwrite(STDERR, "Start MySQL in XAMPP and check DB_* in .env.\n");
    exit(1);
}

$database = mg_db_config()["name"];
if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $database)) {
    fwrite(STDERR, "DB_NAME may contain only letters, digits and underscores.\n");
    exit(1);
}

$lines = [];
$lines[] = "-- MalwareGuard: brand-new system that keeps the login accounts";
$lines[] = "-- Created " . gmdate("Y-m-d H:i") . " UTC by tools/export_for_transfer.php";
$lines[] = "--";
$lines[] = "-- Importing this file REPLACES the `$database` database on the PC you import";
$lines[] = "-- it on: every table is recreated empty (no file events, search activity,";
$lines[] = "-- scans, computers or tokens), and the " . count($users) . " login account(s) below are";
$lines[] = "-- restored with their current passwords.";
$lines[] = "--";
$lines[] = "-- phpMyAdmin: http://localhost/phpmyadmin -> Import -> choose this file -> Import.";
$lines[] = "-- Then add each monitored PC again with a new token (Add a computer).";
$lines[] = "--";
$lines[] = "-- Contains password hashes: keep this file private.";
$lines[] = "";
$lines[] = "DROP DATABASE IF EXISTS `$database`;";
$lines[] = "CREATE DATABASE `$database` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
$lines[] = "USE `$database`;";
$lines[] = "SET NAMES utf8mb4;";
$lines[] = "SET FOREIGN_KEY_CHECKS = 0;";
$lines[] = "";
$lines[] = $tables;
$lines[] = "";
$lines[] = "-- Login accounts (unchanged passwords).";
foreach ($users as $user) {
    $values = array_map(
        static fn ($value): string => $value === null ? "NULL" : $pdo->quote((string) $value),
        [$user["name"], $user["email"], $user["password"], $user["role"], $user["status"], $user["created_at"]]
    );
    $lines[] = "INSERT INTO `users` (`name`, `email`, `password`, `role`, `status`, `created_at`) VALUES (" . implode(", ", $values) . ");";
}
$lines[] = "";
$lines[] = "-- Every migration is already part of the tables above.";
$lines[] = "INSERT INTO `schema_migrations` (`version`) VALUES " . implode(", ", array_map(static fn ($m) => "('" . $m . "')", $migrations)) . ";";
$lines[] = "";
$lines[] = "SET FOREIGN_KEY_CHECKS = 1;";
$lines[] = "";

if (file_put_contents($target, implode("\n", $lines)) === false) {
    fwrite(STDERR, "Cannot write $target\n");
    exit(1);
}

echo "Created: $target\n";
echo "Accounts kept: " . count($users) . "\n";
foreach ($users as $user) {
    echo "  - {$user["email"]} ({$user["role"]})\n";
}
if (!$users) {
    echo "No accounts exist yet. After importing, create one with: php reset_account.php\n";
}
echo "Copy this file to the new PC and import it in phpMyAdmin. Keep it private: it contains password hashes.\n";
