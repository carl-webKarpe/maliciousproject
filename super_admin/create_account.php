<?php
if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit("This script must be run from the command line. Use: php create_super_admin.php\n");
}

require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "db.php";

function ensure_users_role_column_is_compatible(mysqli $conn): void
{
    $columnCheck = $conn->query("SHOW COLUMNS FROM users LIKE 'role'");
    if ($columnCheck === false) {
        throw new RuntimeException("The users table does not exist or is not ready for super-admin provisioning.\n");
    }

    if ($columnCheck->num_rows === 0) {
        $alter = $conn->query("ALTER TABLE users ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user' AFTER email");
        if ($alter === false) {
            throw new RuntimeException("Could not add the users.role column: " . $conn->error . "\n");
        }
        return;
    }

    $column = $columnCheck->fetch_assoc();
    $type = strtoupper((string) ($column["Type"] ?? ""));
    $length = 0;

    if (preg_match('/\d+/', $type, $matches) === 1) {
        $length = (int) $matches[0];
    }

    if (stripos($type, "VARCHAR") !== 0 || $length < 32) {
        $alter = $conn->query("ALTER TABLE users MODIFY role VARCHAR(32) NOT NULL DEFAULT 'user'");
        if ($alter === false) {
            throw new RuntimeException("Could not widen the users.role column for super_admin support: " . $conn->error . "\n");
        }
    }
}

try {
    ensure_users_role_column_is_compatible($conn);
} catch (RuntimeException $e) {
    $conn->close();
    exit($e->getMessage());
}

echo "Super-admin Gmail address: ";
$email = strtolower(trim(fgets(STDIN)));
echo "Super-admin name: ";
$name = trim(fgets(STDIN));
$password = malwareGuardSetting("SUPER_ADMIN_PASSWORD");

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !str_ends_with($email, "@gmail.com")) {
    exit("A valid @gmail.com address is required.\n");
}
if ($name === "" || strlen($name) > 100) {
    exit("A name of 1 to 100 characters is required.\n");
}
if (strlen($password) < 12) {
    exit("Set SUPER_ADMIN_PASSWORD to a password of at least 12 characters before running this script.\n");
}

$check = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
$check->bind_param("s", $email);
$check->execute();
if ($check->get_result()->num_rows !== 0) {
    $check->close();
    $conn->close();
    exit("That email already has an account; no role was changed.\n");
}
$check->close();

$hash = password_hash($password, PASSWORD_DEFAULT);
$stmt = $conn->prepare("INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, 'super_admin', 'active')");
$stmt->bind_param("sss", $name, $email, $hash);
if (!$stmt->execute()) {
    $stmt->close();
    $conn->close();
    exit("Super-admin creation failed. Confirm the role migration has been applied.\n");
}

$stmt->close();
$conn->close();
echo "Super-admin account created.\n";