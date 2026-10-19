<?php

session_start();

require_once "db.php";


// Only allow POST requests

if ($_SERVER["REQUEST_METHOD"] !== "POST") {

    header("Location: login.html");

    exit;
}

$redirectLoginError = static function (string $role, string $error): void {
    if (!in_array($role, ["user", "admin", "super_admin"], true)) {
        $role = "admin";
    }

    header("Location: login.html?role=" . rawurlencode($role) . "&error=" . rawurlencode($error));
    exit;
};


// Get form data

$email = trim($_POST["email"] ?? "");

$password = $_POST["password"] ?? "";

$loginType = $_POST["login_type"] ?? "user";

if (!in_array($loginType, ["user", "admin", "super_admin"], true)) {
    http_response_code(400);
    exit("Invalid login request.");
}


// Validate input

if ($email === "" || $password === "") {
    $conn->close();
    $redirectLoginError($loginType, "required");
}




// Find user

$stmt = $conn->prepare(
    "SELECT id, name, email, password, role, status
     FROM users
     WHERE email = ?
     LIMIT 1"
);

$stmt->bind_param("s", $email);

$stmt->execute();

$result = $stmt->get_result();


// User doesn't exist

if ($result->num_rows !== 1) {

    $stmt->close();

    $conn->close();

    $redirectLoginError($loginType, "invalid");

}


$user = $result->fetch_assoc();

$stmt->close();

$expectedRole = $loginType === "admin" ? "admin" : $loginType;
if (($user["role"] ?? "") !== $expectedRole) {
    $conn->close();
    $redirectLoginError($loginType, "invalid");
}


// Check account status

if ($user["status"] !== "active") {

    $conn->close();

    $redirectLoginError($loginType, "inactive");

}


// Verify password

if (!password_verify($password, $user["password"])) {

    // Record failed login

    $log = $conn->prepare(
        "INSERT INTO login_activity
        (user_id, email, ip_address, user_agent, status)
        VALUES (?, ?, ?, ?, 'failed')"
    );

    $ip = $_SERVER["REMOTE_ADDR"] ?? null;

    $agent = $_SERVER["HTTP_USER_AGENT"] ?? null;

    $log->bind_param(
        "isss",
        $user["id"],
        $email,
        $ip,
        $agent
    );

    $log->execute();

    $log->close();

    $conn->close();

    $redirectLoginError($loginType, "invalid");

}


if (($user["role"] ?? "") === "super_admin") {
    require_once __DIR__ . DIRECTORY_SEPARATOR . "mail_config.php";

    $code = str_pad((string) random_int(0, 999999), 6, "0", STR_PAD_LEFT);
    session_regenerate_id(true);
    unset($_SESSION["logged_in"], $_SESSION["user_id"], $_SESSION["user_name"], $_SESSION["user_email"], $_SESSION["user_role"]);
    unset($_SESSION["super_admin_demo_code"]);
    $_SESSION["pending_super_admin"] = [
        "id" => (int) $user["id"],
        "name" => $user["name"],
        "email" => $user["email"],
        "code_hash" => password_hash($code, PASSWORD_DEFAULT),
        "expires_at" => time() + 300,
        "attempts" => 0,
    ];

    if (MAIL_USER === "" || MAIL_PASS === "") {
        unset($_SESSION["pending_super_admin"]);
        $conn->close();
        http_response_code(503);
        exit("Super-admin email verification is not configured.");
    }

    $autoload = __DIR__ . DIRECTORY_SEPARATOR . "vendor" . DIRECTORY_SEPARATOR . "autoload.php";
    if (!file_exists($autoload)) {
        $conn->close();
        http_response_code(503);
        exit("Email delivery is unavailable.");
    }

    require_once $autoload;

    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = MAIL_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = MAIL_USER;
        $mail->Password = MAIL_PASS;
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = MAIL_PORT;
        $mail->setFrom(MAIL_USER, MAIL_FROM_NAME);
        $mail->addAddress($user["email"], $user["name"]);
        $mail->Subject = "Your MalwareGuard super-admin code";
        $mail->Body = "Your super-admin sign-in code is {$code}. It expires in 5 minutes.";
        $mail->AltBody = $mail->Body;
        $mail->send();
    } catch (Throwable $e) {
        unset($_SESSION["pending_super_admin"]);
        error_log("Super-admin code email failed: " . $e->getMessage());
        $conn->close();
        http_response_code(503);
        if (stripos($e->getMessage(), "authenticate") !== false) {
            exit("Gmail rejected SMTP authentication. Check MAIL_USER and replace MAIL_PASS in .env with a current Google App Password for that Gmail account.");
        }
        exit("Could not send the verification email. Contact the system administrator.");
    }

    $conn->close();
    header("Location: super_admin/verify.php");
    exit;
}


// Regenerate session ID

session_regenerate_id(true);


// Store user information

$_SESSION["user_id"] = $user["id"];

$_SESSION["user_name"] = $user["name"];

$_SESSION["user_email"] = $user["email"];

$_SESSION["user_role"] = $user["role"];

$_SESSION["logged_in"] = true;


// Update last login

$update = $conn->prepare(
    "UPDATE users
     SET last_login = NOW()
     WHERE id = ?"
);

$update->bind_param(
    "i",
    $user["id"]
);

$update->execute();

$update->close();


// Record successful login

$log = $conn->prepare(
    "INSERT INTO login_activity
    (user_id, email, ip_address, user_agent, status)
    VALUES (?, ?, ?, ?, 'success')"
);

$ip = $_SERVER["REMOTE_ADDR"] ?? null;

$agent = $_SERVER["HTTP_USER_AGENT"] ?? null;

$log->bind_param(
    "isss",
    $user["id"],
    $email,
    $ip,
    $agent
);

$log->execute();

$log->close();

$conn->close();


// Redirect based on role
if (($user["role"] ?? "") === "admin") {
    header("Location: admin/dashboard.php");
    exit;
}

header("Location: dashboard.php");

exit;

?>
