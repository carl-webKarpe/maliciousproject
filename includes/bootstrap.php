<?php
// Shared helpers for the device-monitoring features: PDO access, settings,
// rate limiting, audit logging and time conversion. Older pages keep using
// the mysqli connection from db.php; new code uses mg_pdo().

require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "app_config.php";

const MG_AGENT_API_VERSION = 1;

function mg_setting_int(string $key, int $default, int $min, int $max): int
{
    $value = filter_var(malwareGuardSetting($key, (string) $default), FILTER_VALIDATE_INT);
    if ($value === false) {
        return $default;
    }
    return max($min, min($max, $value));
}

function mg_setting_bool(string $key, bool $default = false): bool
{
    $value = strtolower(trim(malwareGuardSetting($key, $default ? "true" : "false")));
    return in_array($value, ["1", "true", "yes", "on"], true);
}

function mg_db_config(): array
{
    return [
        "host" => malwareGuardSetting("DB_HOST", "localhost"),
        "port" => mg_setting_int("DB_PORT", 3306, 1, 65535),
        "name" => malwareGuardSetting("DB_NAME", "malwareguard"),
        "user" => malwareGuardSetting("DB_USER", "root"),
        "pass" => malwareGuardSetting("DB_PASS", ""),
    ];
}

function mg_pdo(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $config = mg_db_config();
    $dsn = sprintf(
        "mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4",
        $config["host"],
        $config["port"],
        $config["name"]
    );
    $pdo = new PDO($dsn, $config["user"], $config["pass"], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

// Seconds between the database clock (NOW()) and UTC. Agents send UTC epoch
// timestamps; converting with this offset keeps them comparable with NOW()
// no matter which time zone the MySQL server or PHP is configured for.
function mg_db_utc_offset(): int
{
    static $offset = null;
    if ($offset === null) {
        $offset = (int) mg_pdo()->query("SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), NOW())")->fetchColumn();
    }
    return $offset;
}

function mg_db_now(): string
{
    return (string) mg_pdo()->query("SELECT NOW()")->fetchColumn();
}

// Converts an agent-supplied UTC epoch into a database-local DATETIME string.
// Values more than five minutes in the future, or missing, become "now".
function mg_epoch_to_db(mixed $epoch): string
{
    $now = time();
    $value = is_numeric($epoch) ? (int) $epoch : $now;
    if ($value <= 0 || $value > $now + 300) {
        $value = $now;
    }
    return gmdate("Y-m-d H:i:s", $value + mg_db_utc_offset());
}

function mg_client_ip(): string
{
    // REMOTE_ADDR only: X-Forwarded-For is client-controlled unless a trusted
    // reverse proxy sets it, and this prototype does not assume one.
    $ip = (string) ($_SERVER["REMOTE_ADDR"] ?? "");
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : "unknown";
}

// Fixed-window counter. Returns true while the caller is under $limit hits
// per $windowSeconds for $bucket.
function mg_rate_limit(string $bucket, int $limit, int $windowSeconds): bool
{
    $pdo = mg_pdo();
    $bucket = substr($bucket, 0, 191);
    $window = intdiv(time(), $windowSeconds) * $windowSeconds;

    $stmt = $pdo->prepare(
        "INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?, ?, 1)
         ON DUPLICATE KEY UPDATE
             hits = IF(window_start = VALUES(window_start), hits + 1, 1),
             window_start = VALUES(window_start)"
    );
    $stmt->execute([$bucket, $window]);

    $hits = $pdo->prepare("SELECT hits FROM rate_limits WHERE bucket = ?");
    $hits->execute([$bucket]);
    return (int) $hits->fetchColumn() <= $limit;
}

function mg_audit(string $actorType, ?string $actorId, string $action, ?string $target = null, array $details = []): void
{
    try {
        $stmt = mg_pdo()->prepare(
            "INSERT INTO audit_log (actor_type, actor_id, action, target, details, ip_address)
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([
            $actorType,
            $actorId,
            $action,
            $target === null ? null : substr($target, 0, 255),
            $details ? json_encode($details, JSON_UNESCAPED_SLASHES) : null,
            PHP_SAPI === "cli" ? null : mg_client_ip(),
        ]);
    } catch (Throwable $e) {
        // Auditing must never break the request it describes.
        error_log("Audit log write failed: " . $e->getMessage());
    }
}

function mg_h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
}

function mg_random_token(int $bytes = 32): string
{
    return rtrim(strtr(base64_encode(random_bytes($bytes)), "+/", "-_"), "=");
}

function mg_hash_secret(string $secret): string
{
    // Tokens and device credentials are 256-bit random values, so a fast hash
    // is sufficient: there is nothing to brute-force from the stored digest.
    return hash("sha256", $secret);
}

// Seconds after the last heartbeat before a device is shown as offline.
function mg_online_window(int $heartbeatInterval): int
{
    return max(mg_setting_int("AGENT_OFFLINE_AFTER_SECONDS", 90, 30, 86400), $heartbeatInterval * 3);
}

function mg_require_admin_session(): array
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $role = $_SESSION["user_role"] ?? "";
    if (
        ($_SESSION["logged_in"] ?? false) !== true ||
        !in_array($role, ["admin", "super_admin"], true) ||
        ($role === "super_admin" && ($_SESSION["super_admin_verified"] ?? false) !== true)
    ) {
        return [];
    }
    return [
        "id" => (int) ($_SESSION["user_id"] ?? 0),
        "role" => $role,
        "name" => (string) ($_SESSION["user_name"] ?? ""),
    ];
}
