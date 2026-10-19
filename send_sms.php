<?php

session_start();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'message' => 'Only POST requests are allowed.'
    ]);
    exit;
}

$phone = trim($_POST['phone_number'] ?? '');

if ($phone === '') {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Phone number is required.'
    ]);
    exit;
}

if (strlen($phone) < 8 || strlen($phone) > 20) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Phone number must be between 8 and 20 characters.'
    ]);
    exit;
}

$code = str_pad((string) random_int(100000, 999999), 6, '0', STR_PAD_LEFT);

$_SESSION['sms_phone'] = $phone;
$_SESSION['sms_code'] = $code;
$_SESSION['sms_expires_at'] = time() + 300;

// Only expose the code when the request comes from the local machine (development).
// On a real server the code must be delivered ONLY by SMS, never in the response.
$isLocal = in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);

// TODO (production): call your SMS provider here (Twilio, Vonage, Semaphore, etc.).

$response = [
    'success' => true,
    'message' => 'Verification code sent successfully.'
];
if ($isLocal) {
    $response['demo_code'] = $code;
}
echo json_encode($response);
