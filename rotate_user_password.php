<?php
// Run from the command line only: php rotate_user_password.php
if (php_sapi_name() !== "cli") { http_response_code(403); exit; }
require_once __DIR__ . DIRECTORY_SEPARATOR . "db.php";

echo "User email: ";
$email = trim(fgets(STDIN));
echo "New password (min 12 chars): ";
$password = trim(fgets(STDIN));
if (strlen($password) < 12) exit("Password too short. Use at least 12 characters.\n");

$hash = password_hash($password, PASSWORD_DEFAULT);
$stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ? AND role = 'user'");
$stmt->bind_param("ss", $hash, $email);
$stmt->execute();
echo $stmt->affected_rows > 0 ? "User password updated.\n" : "No user account with that email.\n";

$stmt->close();
$conn->close();