<?php
session_start();

$pending = $_SESSION["pending_super_admin"] ?? null;
if (!$pending) {
    header("Location: login.html");
    exit;
}

$error = "";
if (empty($_SESSION["super_admin_csrf"])) {
    $_SESSION["super_admin_csrf"] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $code = trim($_POST["code"] ?? "");

    if (!hash_equals($_SESSION["super_admin_csrf"], $_POST["csrf_token"] ?? "")) {
        $error = "The verification form expired. Reload and try again.";
    } else {
        $pending["attempts"]++;
        $_SESSION["pending_super_admin"] = $pending;
    }

    if ($error === "") {
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
    <style>
        body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #101619; color: #f2f5f2; font: 16px "Segoe UI", sans-serif; }
        main { width: min(420px, calc(100% - 40px)); padding: 32px; border: 1px solid #43534c; background: #19221e; }
        h1 { margin-top: 0; font-size: 26px; }
        p { color: #bdc9c0; line-height: 1.5; }
        label { display: block; margin: 22px 0 8px; font-weight: 600; }
        input { width: 100%; box-sizing: border-box; padding: 12px; border: 1px solid #53645b; background: #101714; color: white; font-size: 20px; letter-spacing: 4px; }
        button { width: 100%; margin-top: 16px; padding: 13px; border: 0; background: #a9d6a3; color: #102114; font-weight: 700; cursor: pointer; }
        .error { color: #ff9b9b; }
    </style>
</head>
<body>
    <main>
        <h1>Email verification</h1>
        <p>Enter the six-digit code sent to <?php echo htmlspecialchars($pending["email"], ENT_QUOTES, "UTF-8"); ?>. The code expires in five minutes.</p>
        <?php if ($error !== ""): ?><p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, "UTF-8"); ?></p><?php endif; ?>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION["super_admin_csrf"], ENT_QUOTES, "UTF-8"); ?>">
            <label for="code">Verification code</label>
            <input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
            <button type="submit">Verify and continue</button>
        </form>
    </main>
</body>
</html>