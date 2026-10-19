<?php

session_start();
require_once "db.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: registration.html");
    exit;
}

$pending = $_SESSION["pending_registration"] ?? null;
if (!$pending) {
    die("Registration session expired. Please start again.");
}

$sms_code = trim($_POST["sms_code"] ?? "");
if (!preg_match('/^\d{6}$/', $sms_code)) {
    die("SMS verification code must be a 6-digit number.");
}

// Max 5 guesses per code, then the code is invalidated
$_SESSION["sms_attempts"] = ($_SESSION["sms_attempts"] ?? 0) + 1;
if ($_SESSION["sms_attempts"] > 5) {
    unset($_SESSION["sms_code"], $_SESSION["sms_expires_at"]);
    die("Too many incorrect attempts. Please request a new code.");
}

if (
    !isset($_SESSION["sms_code"], $_SESSION["sms_expires_at"]) ||
    time() > $_SESSION["sms_expires_at"] ||
    !password_verify($sms_code, $_SESSION["sms_code"])
) {
    die("Invalid or expired SMS verification code.");
}

// Email may have been taken since step 1
$check = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
$check->bind_param("s", $pending["email"]);
$check->execute();
if ($check->get_result()->num_rows > 0) {
    $check->close();
    die("An account with this email already exists.");
}
$check->close();

$stmt = $conn->prepare(
    "INSERT INTO users (name, email, password, role, status)
     VALUES (?, ?, ?, 'user', 'active')"
);
$stmt->bind_param("sss", $pending["name"], $pending["email"], $pending["password_hash"]);

if ($stmt->execute()) {
    $stmt->close();
    $conn->close();
    unset($_SESSION["pending_registration"], $_SESSION["sms_code"], $_SESSION["sms_expires_at"], $_SESSION["sms_attempts"], $_SESSION["sms_last_sent"]);
    header("Location: login.html?role=user&registered=1");
    exit;
}

echo "Registration failed.";
$stmt->close();
$conn->close();
