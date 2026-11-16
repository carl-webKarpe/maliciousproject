<?php
session_start();

$pending = $_SESSION["pending_super_admin"] ?? null;
if (!$pending) {
    header("Location: login.html");
    exit;
}

$error = "";
$success = "";
if (empty($_SESSION["super_admin_csrf"])) {
    $_SESSION["super_admin_csrf"] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $code = trim($_POST["code"] ?? "");

    if (!hash_equals($_SESSION["super_admin_csrf"], $_POST["csrf_token"] ?? "")) {
        $error = "The verification form expired. Reload and try again.";
    } elseif (($_POST["action"] ?? "") === "resend") {
        require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "mail_config.php";
        $autoload = __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "vendor" . DIRECTORY_SEPARATOR . "autoload.php";

        if (MAIL_USER === "" || MAIL_PASS === "" || !file_exists($autoload)) {
            $error = "Email verification is not configured. Sign in again or contact the administrator.";
        } else {
            $code = str_pad((string) random_int(0, 999999), 6, "0", STR_PAD_LEFT);
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
                $mail->addAddress($pending["email"], $pending["name"]);
                $mail->Subject = "Your MalwareGuard super-admin code";
                $mail->Body = "Your new super-admin sign-in code is {$code}. It expires in 5 minutes.";
                $mail->AltBody = $mail->Body;
                $mail->send();

                $pending["code_hash"] = password_hash($code, PASSWORD_DEFAULT);
                $pending["expires_at"] = time() + 300;
                $pending["attempts"] = 0;
                $_SESSION["pending_super_admin"] = $pending;
                $success = "A new verification code has been sent.";
            } catch (Throwable $e) {
                error_log("Super-admin code resend failed: " . $e->getMessage());
                $error = "Could not resend the verification code. Try again later.";
            }
        }
    } else {
        $pending["attempts"]++;
        $_SESSION["pending_super_admin"] = $pending;
    }

    if ($error === "" && ($_POST["action"] ?? "") !== "resend") {
        if ($pending["attempts"] > 5 || time() > $pending["expires_at"]) {
            unset($_SESSION["pending_super_admin"]);
            $error = "This verification request expired. Sign in again.";
        } elseif (!preg_match('/^\d{6}$/', $code) || !password_verify($code, $pending["code_hash"])) {
            $error = "That code is invalid. Check the email and try again.";
        } else {
            require_once __DIR__ . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "db.php";
            $account = $conn->prepare("SELECT name, email, role, status FROM users WHERE id = ? LIMIT 1");
            $account->bind_param("i", $pending["id"]);
            $account->execute();
            $currentUser = $account->get_result()->fetch_assoc();
            $account->close();

            if (!$currentUser || $currentUser["role"] !== "super_admin" || $currentUser["status"] !== "active") {
                unset($_SESSION["pending_super_admin"]);
                $conn->close();
                $error = "This account is not permitted to sign in.";
            } else {
                session_regenerate_id(true);
                $_SESSION["user_id"] = $pending["id"];
                $_SESSION["user_name"] = $currentUser["name"];
                $_SESSION["user_email"] = $currentUser["email"];
                $_SESSION["user_role"] = "super_admin";
                $_SESSION["logged_in"] = true;
                $_SESSION["super_admin_verified"] = true;
                unset($_SESSION["pending_super_admin"], $_SESSION["super_admin_csrf"], $_SESSION["super_admin_demo_code"]);

                $update = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $update->bind_param("i", $_SESSION["user_id"]);
                $update->execute();
                $update->close();

                $ip = $_SERVER["REMOTE_ADDR"] ?? null;
                $agent = $_SERVER["HTTP_USER_AGENT"] ?? null;
                $log = $conn->prepare("INSERT INTO login_activity (user_id, email, ip_address, user_agent, status) VALUES (?, ?, ?, ?, 'success')");
                $log->bind_param("isss", $_SESSION["user_id"], $_SESSION["user_email"], $ip, $agent);
                $log->execute();
                $log->close();
                $conn->close();

                header("Location: dashboard.php");
                exit;
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Super Admin | MalwareGuard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link rel="stylesheet" href="../assets/css/auth.css">
    <style>
        body { align-items: center; justify-items: center; padding: 32px 20px; }
        .access-card { width: min(430px, calc(100vw - 40px)); padding: 40px 28px 28px; text-align: center; }
        .access-icon { width: 70px; height: 70px; display: grid; place-items: center; margin: 0 auto 20px; color: var(--pink); font-size: 34px; }
        .access-icon i { filter: drop-shadow(0 0 16px var(--pink-glow)); }
        .access-card h1 { margin: 0 0 10px; font-size: 34px; line-height: 1.18; letter-spacing: -.5px; }
        .access-card > p { max-width: 330px; margin: 0 auto 22px; font-size: 15px; line-height: 1.55; }
        .code-inputs { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; }
        .code-input { width: 100%; height: 62px; padding: 0; border: 1px solid var(--border); border-radius: 12px; background: var(--field-bg); color: var(--text); text-align: center; font-size: 28px; font-weight: 700; }
        .verify-btn { width: 100%; height: 54px; margin: 26px 0 0; border: 0; border-radius: 12px; background: linear-gradient(135deg, var(--pink), var(--pink-dark)); color: #fff; font: 700 16px/1 "Segoe UI", sans-serif; cursor: pointer; box-shadow: 0 14px 32px rgba(217,54,124,.28), 0 0 26px var(--pink-glow); }
        .status-box { min-height: 48px; margin: 18px 0 0; padding: 12px; border: 1px solid transparent; border-radius: 9px; background: transparent; color: var(--muted); font-size: 13px; line-height: 1.5; }
        .status-box.error { border-color: rgba(255,79,154,.24); background: rgba(255,79,154,.08); color: var(--danger); }
        .status-box.success { border-color: rgba(115,223,172,.28); background: rgba(115,223,172,.08); color: var(--success); }
        .resend-text { margin: 18px 0 0; color: var(--muted); font-size: 14px; }
        .resend-btn,
        button.resend-btn[type="submit"] { min-height: 0; padding: 0; border: 0; border-radius: 0; background: transparent; color: var(--pink); box-shadow: none; font: 700 14px/1 "Segoe UI", sans-serif; filter: none; cursor: pointer; }
        .resend-btn:hover,
        button.resend-btn[type="submit"]:hover { transform: none; border: 0; background: transparent; color: var(--pink-light); box-shadow: none; filter: none; }
        .back-link { display: block; margin-top: 18px; color: var(--pink); font-size: 14px; font-weight: 700; }
        @media (max-width:480px) { .access-card { width: 100%; padding: 34px 18px 24px; } .access-card h1 { font-size: 29px; } .code-inputs { gap: 7px; } .code-input { height: 54px; font-size: 24px; } }
    </style>
</head>
<body>
    <main class="auth-card access-card">
        <div class="access-icon"><i class="fa-solid fa-shield-halved"></i></div>
        <h1>Enter Access Code</h1>
        <p>A 6-digit code has been sent to the email address you registered with.</p>

        <form id="verificationForm" method="post" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["super_admin_csrf"], ENT_QUOTES, "UTF-8"); ?>">
            <input id="code" name="code" type="hidden">
            <div class="code-inputs" role="group" aria-label="Six-digit verification code">
                <?php for ($i = 0; $i < 6; $i++): ?>
                <input class="code-input" type="text" inputmode="numeric" pattern="[0-9]" maxlength="1" aria-label="Verification digit <?php echo $i + 1; ?>" <?php echo $i === 0 ? "autofocus" : ""; ?>>
                <?php endfor; ?>
            </div>
            <button class="verify-btn" type="submit">Verify Code</button>
        </form>

        <?php $status = $error ?: $success; ?>
        <div id="statusBox" class="status-box<?php echo $status === "" ? "" : ($error !== "" ? " error" : " success"); ?>" role="status" <?php echo $status === "" ? "hidden" : ""; ?>><?php echo htmlspecialchars($status, ENT_QUOTES, "UTF-8"); ?></div>

        <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["super_admin_csrf"], ENT_QUOTES, "UTF-8"); ?>">
            <input type="hidden" name="action" value="resend">
            <p class="resend-text">Didn't receive it? <button class="resend-btn" type="submit">Resend</button></p>
        </form>
        <a class="back-link" href="../login.html?role=super_admin">Back to login</a>
    </main>

    <script>
        const inputs = Array.from(document.querySelectorAll('.code-input'));
        const codeField = document.getElementById('code');
        const form = document.getElementById('verificationForm');
        const statusBox = document.getElementById('statusBox');

        function showStatus(message) {
            statusBox.textContent = message;
            statusBox.className = 'status-box error';
            statusBox.hidden = false;
        }

        inputs.forEach((input, index) => {
            input.addEventListener('input', () => {
                input.value = input.value.replace(/\D/g, '').slice(-1);
                codeField.value = inputs.map(item => item.value).join('');
                if (input.value && index < inputs.length - 1) inputs[index + 1].focus();
            });
            input.addEventListener('keydown', event => {
                if (event.key === 'Backspace' && !input.value && index > 0) inputs[index - 1].focus();
            });
        });

        form.addEventListener('paste', event => {
            const digits = (event.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '').slice(0, 6);
            if (!digits) return;
            event.preventDefault();
            digits.split('').forEach((digit, index) => { if (inputs[index]) inputs[index].value = digit; });
            codeField.value = digits;
            inputs[Math.min(digits.length, 6) - 1].focus();
        });

        form.addEventListener('submit', event => {
            codeField.value = inputs.map(item => item.value).join('');
            if (!/^\d{6}$/.test(codeField.value)) {
                event.preventDefault();
                showStatus('Please enter the full 6-digit code.');
                inputs.find(item => !item.value)?.focus();
            }
        });
    </script>
</body>
</html>