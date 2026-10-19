<?php

if (!function_exists('malwareGuardSetting')) {
    function malwareGuardSetting(string $key, string $default = ''): string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

        if (is_string($value) && $value !== '') {
            return $value;
        }

        if (is_array($value) && count($value) > 0) {
            return (string) array_values($value)[0];
        }

        return $default;
    }
}

$autoload = __DIR__ . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (file_exists($autoload)) {
    require_once $autoload;
}

if (class_exists('Dotenv\\Dotenv')) {
    $dotenvFile = __DIR__ . DIRECTORY_SEPARATOR . '.env';
    if (file_exists($dotenvFile)) {
        \Dotenv\Dotenv::createMutable(__DIR__)->safeLoad();
    }
}

foreach (['APP_NAME', 'VIRUSTOTAL_API_KEY', 'OPENAI_API_KEY'] as $key) {
    if (!isset($_ENV[$key]) && !isset($_SERVER[$key]) && getenv($key) === false) {
        $_ENV[$key] = malwareGuardSetting($key, '');
    }
}

if (!defined('APP_NAME')) {
    define('APP_NAME', malwareGuardSetting('APP_NAME', 'MalwareGuard'));
}
