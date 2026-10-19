<?php

$token = getenv('ENDPOINT_AGENT_TOKEN') ?: 'demo-endpoint-token';
$baseUrl = 'http://localhost:8000/api/agent.php';

function postJson(string $url, string $token, array $payload): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-Agent-Token: ' . $token,
            'Accept: application/json',
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $decoded = json_decode($response ?: '[]', true);
    return [
        'http_code' => $httpCode,
        'body' => is_array($decoded) ? $decoded : ['raw' => (string) $response],
    ];
}

$deviceId = 'demo-device-' . date('YmdHis');
$sessionId = 'session-' . date('YmdHis');

$register = postJson($baseUrl, $token, [
    'action' => 'register',
    'device_id' => $deviceId,
    'hostname' => 'DEMO-PC',
    'username' => 'demo-user',
    'os_name' => 'Windows 11',
    'seen_at' => date('Y-m-d H:i:s'),
]);

$heartbeat = postJson($baseUrl, $token, [
    'action' => 'heartbeat',
    'device_id' => $deviceId,
    'session_id' => $sessionId,
    'username' => 'demo-user',
    'active_window' => 'MalwareGuard Dashboard',
    'cpu_percent' => 28.5,
    'memory_mb' => 1842.3,
    'network_status' => 'online',
    'seen_at' => date('Y-m-d H:i:s'),
]);

$processes = postJson($baseUrl, $token, [
    'action' => 'processes',
    'device_id' => $deviceId,
    'seen_at' => date('Y-m-d H:i:s'),
    'processes' => [
        [
            'name' => 'chrome.exe',
            'pid' => 1234,
            'cpu_percent' => 18.2,
            'memory_mb' => 480.1,
            'window_title' => 'MalwareGuard - Browser',
            'status' => 'running',
        ],
        [
            'name' => 'explorer.exe',
            'pid' => 4321,
            'cpu_percent' => 6.7,
            'memory_mb' => 321.7,
            'window_title' => 'File Explorer',
            'status' => 'running',
        ],
    ],
]);

foreach (['register' => $register, 'heartbeat' => $heartbeat, 'processes' => $processes] as $label => $result) {
    echo "[$label] HTTP {$result['http_code']}\n";
    echo json_encode($result['body'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
}
