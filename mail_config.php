<?php
$autoload = __DIR__ . DIRECTORY_SEPARATOR . "vendor" . DIRECTORY_SEPARATOR . "autoload.php";
if (!is_file($autoload)) {
	throw new RuntimeException("Composer dependencies are missing. Run composer install.");
}
require_once $autoload;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

$mailSetting = static function (string $key, string $default = ''): string {
	$value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
	return $value === false || $value === null || $value === '' ? $default : (string) $value;
};

define('MAIL_HOST', $mailSetting('MAIL_HOST', 'smtp.gmail.com'));
define('MAIL_PORT', (int) $mailSetting('MAIL_PORT', '587'));

define('MAIL_USER', $mailSetting('MAIL_USER'));
define('MAIL_PASS', $mailSetting('MAIL_PASS'));

define('MAIL_FROM_NAME', $mailSetting('MAIL_FROM_NAME', 'MalwareGuard'));
