<?php

session_start();
header("Content-Type: application/json");

require_once __DIR__ . DIRECTORY_SEPARATOR . "mail_config.php";

function out(array $d, int $code = 200): void { http_response_code($code); echo json_encode($d); exit; }

if ($_SERVER["REQUEST_METHOD"] !== "POST") out(["success" => false, "message" => "Only POST requests are allowed."], 405);

$pending = $_SESSION["pending_registration"] ?? null;
if (!$pending) out(["success" => false, "message" => "Registration session expired. Please start again."], 400);

// 30-second cooldown between emails
if (time() - ($_SESSION["sms_last_sent"] ?? 0) < 30) {
    out(["success" => false, "message" => "Please wait a few seconds before requesting another code."], 429);
}

$code = str_pad((string) random_int(0, 999999), 6, "0", STR_PAD_LEFT);

$_SESSION["sms_code"] = password_hash($code, PASSWORD_DEFAULT); // stored hashed
$_SESSION["sms_expires_at"] = time() + 600;                     // 10 minutes
$_SESSION["sms_attempts"] = 0;
$_SESSION["sms_last_sent"] = time();

$isLocal = in_array($_SERVER["REMOTE_ADDR"] ?? "", ["127.0.0.1", "::1"], true);

if (MAIL_USER === "" || MAIL_PASS === "") {
    if ($isLocal) {
        out(["success" => true, "message" => "Development mode: code stored locally.", "demo_code" => $code], 200);
    }
    out(["success" => false, "message" => "Email is not configured. Add MAIL_USER and MAIL_PASS to the project .env file."], 500);
}

$autoload = __DIR__ . "/vendor/autoload.php";
if (!file_exists($autoload)) out(["success" => false, "message" => "PHPMailer is not installed (run: composer require phpmailer/phpmailer)."], 500);
require_once $autoload;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

try {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = MAIL_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = MAIL_USER;
    $mail->Password   = MAIL_PASS;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = MAIL_PORT;

    $mail->setFrom(MAIL_USER, MAIL_FROM_NAME);
    $mail->addAddress($pending["email"], $pending["name"]);
    $mail->isHTML(true);
    $mail->Subject = "Your MalwareGuard verification code";
    $name = htmlspecialchars($pending["name"], ENT_QUOTES, "UTF-8");
    $mail->Body    = "<p>Hi {$name},</p>"
                   . "<p>Your MalwareGuard verification code is:</p>"
                   . "<h2 style=\"letter-spacing:6px\">{$code}</h2>"
                   . "<p>It expires in 10 minutes. If you didn't request this, ignore this email.</p>";
    $mail->AltBody = "Your MalwareGuard verification code is {$code}. It expires in 10 minutes.";
    $mail->send();
} catch (Exception $e) {
    error_log("Mail error: " . $e->getMessage());
    if ($isLocal) {
        out(["success" => true, "message" => "Development mode: email delivery skipped locally.", "demo_code" => $code], 200);
    }
    // On localhost, show the real reason so you can fix it. On a real server, stay generic.
    $msg = $isLocal ? "Mail error: " . $e->getMessage() : "Could not send the email. Check your mail settings.";
    out(["success" => false, "message" => $msg], 500);
}

out(["success" => true, "message" => "Verification code emailed."]);
