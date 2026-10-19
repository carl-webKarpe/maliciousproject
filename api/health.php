<?php
// Public health check used by START_MALICIOUSPROJECT.bat and `agent.py check`.
// Reports only whether the application and database work; no configuration
// values or secrets are returned.

require_once __DIR__ . "/../includes/bootstrap.php";

header("Content-Type: application/json");
header("Cache-Control: no-store");

$status = [
    "ok" => true,
    "app" => APP_NAME,
    "agent_api_version" => MG_AGENT_API_VERSION,
    "server_time" => time(),
    "database" => "ok",
    "schema" => "ok",
];

try {
    $pdo = mg_pdo();
    $migrationFiles = glob(__DIR__ . "/../database/migrations/*.sql") ?: [];
    $applied = (int) $pdo->query("SELECT COUNT(*) FROM schema_migrations")->fetchColumn();
    if ($applied < count($migrationFiles)) {
        $status["ok"] = false;
        $status["schema"] = "migrations_pending";
    }
} catch (Throwable $e) {
    error_log("Health check database error: " . $e->getMessage());
    $status["ok"] = false;
    $status["database"] = "unavailable";
    $status["schema"] = "unknown";
}

http_response_code($status["ok"] ? 200 : 503);
echo json_encode($status, JSON_UNESCAPED_SLASHES);
