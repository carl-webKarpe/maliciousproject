<?php

$host = getenv("DB_HOST") ?: "localhost";
$username = getenv("DB_USER") ?: "root";
$password = getenv("DB_PASS") ?: "";
$database = getenv("DB_NAME") ?: "malwareguard";

$bootstrapConnection = @new mysqli($host, $username, $password);
if ($bootstrapConnection->connect_error) {
    die("Database connection failed: " . $bootstrapConnection->connect_error);
}

$escapedDatabase = $bootstrapConnection->real_escape_string($database);
$databaseCheck = $bootstrapConnection->query(
    "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$escapedDatabase' LIMIT 1"
);

if ($databaseCheck === false || $databaseCheck->num_rows === 0) {
    $createDbResult = $bootstrapConnection->query(
        "CREATE DATABASE IF NOT EXISTS `$escapedDatabase` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    );
    if ($createDbResult === false) {
        $bootstrapConnection->close();
        die("Could not create database '$database': " . $bootstrapConnection->error);
    }
}

if ($databaseCheck !== false) {
    $databaseCheck->free_result();
}

$bootstrapConnection->close();

$conn = new mysqli(
    $host,
    $username,
    $password,
    $database
);

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$conn->set_charset("utf8mb4");

function ensureDatabaseSchema(mysqli $conn): void
{
    $schemaStatements = [
        "CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'user',
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            last_login DATETIME NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS login_activity (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id INT UNSIGNED NOT NULL,
            email VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) DEFAULT NULL,
            user_agent TEXT DEFAULT NULL,
            status VARCHAR(32) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_login_activity_user_id (user_id),
            KEY idx_login_activity_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS scans (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id INT UNSIGNED NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            original_file_name VARCHAR(255) NOT NULL,
            file_path VARCHAR(255) NOT NULL,
            file_size BIGINT UNSIGNED NOT NULL,
            file_type VARCHAR(255) DEFAULT NULL,
            file_extension VARCHAR(64) DEFAULT NULL,
            file_hash CHAR(64) NOT NULL,
            threat_level VARCHAR(32) NOT NULL DEFAULT 'safe',
            detection_status VARCHAR(32) NOT NULL DEFAULT 'safe',
            security_score INT NOT NULL DEFAULT 0,
            detection_count INT NOT NULL DEFAULT 0,
            analysis_result TEXT DEFAULT NULL,
            scan_engine VARCHAR(128) NOT NULL DEFAULT 'MalwareGuard Engine',
            scanned_at DATETIME NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_scans_user_id (user_id),
            KEY idx_scans_scanned_at (scanned_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS detection_results (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_id BIGINT UNSIGNED NOT NULL,
            detection_type VARCHAR(64) NOT NULL DEFAULT 'general',
            detection_name VARCHAR(128) NOT NULL,
            severity VARCHAR(32) NOT NULL DEFAULT 'low',
            description TEXT NOT NULL,
            evidence TEXT DEFAULT NULL,
            score INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_detection_results_scan_id (scan_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS endpoint_devices (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            device_id VARCHAR(128) NOT NULL,
            hostname VARCHAR(255) DEFAULT NULL,
            username VARCHAR(255) DEFAULT NULL,
            os_name VARCHAR(255) DEFAULT NULL,
            last_seen_at DATETIME NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_device_id (device_id),
            KEY idx_endpoint_devices_last_seen (last_seen_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS endpoint_sessions (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            device_id VARCHAR(128) NOT NULL,
            session_id VARCHAR(128) NOT NULL,
            user_name VARCHAR(255) DEFAULT NULL,
            active_window VARCHAR(255) DEFAULT NULL,
            cpu_percent DECIMAL(5,2) DEFAULT 0.00,
            memory_mb DECIMAL(10,2) DEFAULT 0.00,
            network_status VARCHAR(64) DEFAULT 'unknown',
            seen_at DATETIME NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_endpoint_sessions_device_id (device_id),
            KEY idx_endpoint_sessions_seen_at (seen_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS endpoint_processes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            device_id VARCHAR(128) NOT NULL,
            process_name VARCHAR(255) NOT NULL,
            process_id INT UNSIGNED NOT NULL,
            cpu_percent DECIMAL(5,2) DEFAULT 0.00,
            memory_mb DECIMAL(10,2) DEFAULT 0.00,
            window_title VARCHAR(255) DEFAULT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'running',
            seen_at DATETIME NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_endpoint_processes_device_id (device_id),
            KEY idx_endpoint_processes_seen_at (seen_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        "CREATE TABLE IF NOT EXISTS endpoint_alerts (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            device_id VARCHAR(128) NOT NULL,
            alert_type VARCHAR(64) NOT NULL,
            severity VARCHAR(32) NOT NULL DEFAULT 'medium',
            message TEXT NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_endpoint_alerts_device_id (device_id),
            KEY idx_endpoint_alerts_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    ];

    foreach ($schemaStatements as $statement) {
        $result = $conn->query($statement);
        if ($result === false) {
            throw new RuntimeException("Failed to create required database schema: " . $conn->error);
        }
    }

    $userColumns = $conn->query("SHOW COLUMNS FROM users");
    if ($userColumns !== false) {
        $existingColumns = [];
        while ($column = $userColumns->fetch_assoc()) {
            $existingColumns[$column["Field"]] = true;
        }

        if (!isset($existingColumns["role"])) {
            $conn->query("ALTER TABLE users ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user' AFTER email");
        } else {
            $conn->query("ALTER TABLE users MODIFY role VARCHAR(32) NOT NULL DEFAULT 'user'");
        }

        if (!isset($existingColumns["status"])) {
            $conn->query("ALTER TABLE users ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'active' AFTER role");
        }

        if (!isset($existingColumns["last_login"])) {
            $conn->query("ALTER TABLE users ADD COLUMN last_login DATETIME NULL DEFAULT NULL AFTER status");
        }
    }
}

try {
    ensureDatabaseSchema($conn);
} catch (RuntimeException $e) {
    $conn->close();
    die($e->getMessage());
}

?>
