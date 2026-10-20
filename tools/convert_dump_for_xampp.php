<?php
// Makes a MySQL 8 / MySQL Workbench export importable into XAMPP's MariaDB.
//
//   php tools/convert_dump_for_xampp.php  C:\path\to\export.sql
//
// Writes  export-xampp.sql  next to the original (the original is not changed).
// MariaDB does not know MySQL 8's utf8mb4_0900_* collations and a few
// MySQL-8-only table options, so importing a Workbench export fails with
// "Unknown collation". This replaces them with MariaDB equivalents.

if (PHP_SAPI !== "cli") {
    http_response_code(403);
    exit;
}

$source = $argv[1] ?? "";
if ($source === "" || !is_file($source)) {
    fwrite(STDERR, "Usage: php tools/convert_dump_for_xampp.php C:\\path\\to\\export.sql\n");
    exit(1);
}

$sql = file_get_contents($source);
if ($sql === false) {
    fwrite(STDERR, "Cannot read $source\n");
    exit(1);
}

// Workbench may save UTF-16 on some systems; MariaDB expects UTF-8.
if (str_starts_with($sql, "\xFF\xFE") || str_starts_with($sql, "\xFE\xFF")) {
    $sql = mb_convert_encoding($sql, "UTF-8", "UTF-16");
}
$sql = preg_replace('/^\xEF\xBB\xBF/', "", $sql);

$replacements = [
    // MySQL 8 collations -> MariaDB collations
    '/\butf8mb4_0900_(?:ai_ci|as_ci|as_cs|bin)\b/' => "utf8mb4_unicode_ci",
    '/\butf8mb4_[a-z]+_0900_(?:ai_ci|as_cs|as_ci)\b/' => "utf8mb4_unicode_ci",
    // MySQL 8 table options MariaDB rejects
    "/\\/\\*!80016 DEFAULT ENCRYPTION='N' \\*\\/ ?/" => "",
    "/ ?DEFAULT ENCRYPTION='N'/" => "",
    // Definers name accounts that may not exist in XAMPP
    '/\/\*!50017 DEFINER=`[^`]*`@`[^`]*`\s*\*\/ ?/' => "",
    '/ DEFINER=`[^`]*`@`[^`]*`/' => "",
    // MySQL 8 session settings unknown to MariaDB
    '/^\/\*!80000 SET[^\n]*\n/m' => "",
    '/^SET @@SESSION\.SQL_LOG_BIN[^\n]*\n/m' => "",
    '/^SET @@GLOBAL\.GTID_PURGED[^\n]*;\n?/ms' => "",
];

$changes = 0;
foreach ($replacements as $pattern => $replacement) {
    $sql = preg_replace($pattern, $replacement, $sql, -1, $count);
    $changes += $count;
}

$target = preg_replace('/\.sql$/i', "", $source) . "-xampp.sql";
if (file_put_contents($target, $sql) === false) {
    fwrite(STDERR, "Cannot write $target\n");
    exit(1);
}

echo "Converted: $target ($changes change" . ($changes === 1 ? "" : "s") . ")\n";
echo "Import it in phpMyAdmin (Import tab) or with:\n";
echo "  C:\\xampp\\mysql\\bin\\mysql.exe -u root < \"$target\"\n";
