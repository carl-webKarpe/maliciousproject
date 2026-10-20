<?php
// Reset (or create) an admin or super-admin account from the command line:
//
//   php reset_account.php
//
// Lets you change the name, email and password of an existing account, or
// create one if none exists. Also clears the sign-in lockout for it.
// Run it on the server, never through a browser.

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit;
}

require_once __DIR__ . DIRECTORY_SEPARATOR . "includes" . DIRECTORY_SEPARATOR . "bootstrap.php";

function ask(string $question, string $default = ""): string
{
    echo $question . ($default !== "" ? " [$default]" : "") . ": ";
    $answer = trim((string) fgets(STDIN));
    return $answer === "" ? $default : $answer;
}

try {
    $pdo = mg_pdo();
} catch (Throwable $e) {
    exit("Cannot connect to the database: " . $e->getMessage() . "\nCheck that MySQL is running and DB_* in .env are correct.\n");
}

echo "\nMalwareGuard account reset\n==========================\n";
echo "  1) Admin\n  2) Super admin\n";
$choice = ask("Which account type? (1 or 2)", "1");
$role = $choice === "2" ? "super_admin" : "admin";
$roleLabel = $role === "super_admin" ? "super admin" : "admin";

$list = $pdo->prepare("SELECT id, name, email, status FROM users WHERE role = ? ORDER BY id");
$list->execute([$role]);
$accounts = $list->fetchAll();

$account = null;
if ($accounts) {
    echo "\nExisting $roleLabel accounts:\n";
    foreach ($accounts as $i => $row) {
        printf("  %d) %s <%s>%s\n", $i + 1, $row["name"], $row["email"], $row["status"] === "active" ? "" : " (inactive)");
    }
    echo "  N) Create a new $roleLabel\n";
    $pick = strtoupper(ask("Choose an account to reset", "1"));
    if ($pick !== "N") {
        $index = (int) $pick - 1;
        if (!isset($accounts[$index])) {
            exit("No such choice.\n");
        }
        $account = $accounts[$index];
    }
} else {
    echo "\nNo $roleLabel account exists yet, so a new one will be created.\n";
}

$name = ask("Name", $account["name"] ?? "");
$email = strtolower(ask("Email (used to sign in)", $account["email"] ?? ""));
if ($name === "" || mb_strlen($name) > 100) {
    exit("A name of 1 to 100 characters is required.\n");
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    exit("That is not a valid email address.\n");
}
if ($role === "super_admin") {
    echo "Note: super-admin sign-in sends a 6-digit code to this email, so it must be a real inbox you can open,\n";
    echo "and MAIL_USER / MAIL_PASS in .env must be set.\n";
}

echo "The password is shown while you type it; make sure nobody is watching.\n";
$password = ask("New password (at least 12 characters)");
if (strlen($password) < 12) {
    exit("Password too short. Nothing was changed.\n");
}
if (ask("Type the password again") !== $password) {
    exit("The passwords do not match. Nothing was changed.\n");
}

$taken = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id <> ?");
$taken->execute([$email, $account["id"] ?? 0]);
if ($taken->fetchColumn()) {
    exit("Another account already uses $email. Nothing was changed.\n");
}

$hash = password_hash($password, PASSWORD_DEFAULT);
if ($account) {
    $pdo->prepare("UPDATE users SET name = ?, email = ?, password = ?, status = 'active' WHERE id = ? AND role = ?")
        ->execute([$name, $email, $hash, $account["id"], $role]);
    mg_audit("system", null, "account.reset", "user:" . $account["id"], ["role" => $role]);
} else {
    $pdo->prepare("INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, ?, 'active')")
        ->execute([$name, $email, $hash, $role]);
    mg_audit("system", null, "account.created", "user:" . $pdo->lastInsertId(), ["role" => $role]);
}

// Clear sign-in lockouts so the new details work immediately.
$pdo->exec("DELETE FROM rate_limits WHERE bucket LIKE 'login:%'");

$url = $role === "super_admin" ? "super_admin/login.html" : "admin/login.html";
echo "\nDone. The $roleLabel account is ready:\n";
echo "  Email   : $email\n";
echo "  Sign in : http://YOUR-SERVER:PORT/$url (choose \"" . ($role === "super_admin" ? "Super admin" : "Admin") . "\")\n\n";
