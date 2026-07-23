<?php

require_once __DIR__ . '/src/Config/EnvLoader.php';
\App\Config\EnvLoader::load(__DIR__ . '/.env');

$db_host = getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('DB_USER');
$db_pass = getenv('DB_PASS');
$db_name = getenv('DB_NAME');
$db_port = getenv('DB_PORT') ?: 3306;

mysqli_report(MYSQLI_REPORT_OFF);

$mysqli = @new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);

if ($mysqli->connect_error) {
    // Try production/fallback if local fails
    $prod_host = getenv('PROD_DB_HOST');
    $prod_user = getenv('PROD_DB_USER');
    $prod_pass = getenv('PROD_DB_PASS');
    $prod_name = getenv('PROD_DB_NAME');
    
    if ($prod_host) {
        $mysqli = @new mysqli($prod_host, $prod_user, $prod_pass, $prod_name, $db_port);
        if ($mysqli->connect_error) {
            $mysqli = null;
        }
    } else {
        $mysqli = null;
    }
}
?>
