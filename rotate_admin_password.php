<?php
// Run from the command line ONLY:  php rotate_admin_password.php
if (php_sapi_name() !== "cli") { http_response_code(403); exit; }
require_once __DIR__ . DIRECTORY_SEPARATOR . "db.php";

echo "Admin email: ";
$email = trim(fgets(STDIN));
echo "New password (min 12 chars): ";
$pw = trim(fgets(STDIN));
if (strlen($pw) < 12) exit("Password too short.\n");

$hash = password_hash($pw, PASSWORD_DEFAULT);
$stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ? AND role = 'admin'");
$stmt->bind_param("ss", $hash, $email);
$stmt->execute();
echo $stmt->affected_rows > 0 ? "Admin password updated.\n" : "No admin with that email.\n";
