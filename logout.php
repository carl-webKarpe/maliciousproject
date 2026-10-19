<?php

session_start();


// Record logout if user is logged in

if (isset($_SESSION["user_id"])) {

    require_once "db.php";

    $user_id = $_SESSION["user_id"];

    $email = $_SESSION["user_email"] ?? null;

    $ip = $_SERVER["REMOTE_ADDR"] ?? null;

    $agent = $_SERVER["HTTP_USER_AGENT"] ?? null;


    $stmt = $conn->prepare(
        "INSERT INTO login_activity
        (user_id, email, ip_address, user_agent, status)
        VALUES (?, ?, ?, ?, 'logout')"
    );


    $stmt->bind_param(
        "isss",
        $user_id,
        $email,
        $ip,
        $agent
    );


    $stmt->execute();

    $stmt->close();

    $conn->close();
}


$loginDestination = ($_SESSION["user_role"] ?? "") === "user"
    ? "login.html?role=user"
    : "login.html";

// Destroy session

$_SESSION = [];

session_destroy();


// Return to login

header("Location: " . $loginDestination);

exit;

?>
