<?php
// Step 1 of registration. Validates the form and keeps the pending account in the
// server session (password already hashed) instead of the browser's sessionStorage.
session_start();
header("Content-Type: application/json");
require_once "db.php";

function fail(string $msg, int $code = 400): void {
    http_response_code($code);
    echo json_encode(["success" => false, "message" => $msg]);
    exit;
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") fail("POST only.", 405);

$name = trim($_POST["name"] ?? "");
$email = trim($_POST["email"] ?? "");
$password = $_POST["password"] ?? "";
$confirm = $_POST["confirm_password"] ?? "";
$phone = trim($_POST["phone_number"] ?? "");

if ($name === "" || mb_strlen($name) > 100) fail("Please enter your name.");
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail("Please enter a valid email address.");
if (strlen($password) < 8) fail("Password must contain at least 8 characters.");
if ($password !== $confirm) fail("Passwords do not match.");
if (!preg_match('/^\+?[0-9 ()-]{8,20}$/', $phone)) fail("Please enter a valid phone number.");

$check = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
$check->bind_param("s", $email);
$check->execute();
if ($check->get_result()->num_rows > 0) fail("An account with this email already exists.");
$check->close();
$conn->close();

session_regenerate_id(true);
unset($_SESSION["sms_code"], $_SESSION["sms_expires_at"], $_SESSION["sms_attempts"], $_SESSION["sms_last_sent"]);
$_SESSION["pending_registration"] = [
    "name" => $name,
    "email" => $email,
    "password_hash" => password_hash($password, PASSWORD_DEFAULT),
    "phone" => $phone,
];

$digits = preg_replace("/\D/", "", $phone);
echo json_encode(["success" => true, "masked_phone" => "******" . substr($digits, -3)]);
