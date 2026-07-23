<?php

if (basename($_SERVER['PHP_SELF']) == basename(__FILE__)) {
    header("HTTP/1.1 403 Forbidden");
    exit("Direct access not allowed.");
}

ob_start();
date_default_timezone_set('UTC');
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

if (!defined('TOOLS_ROOT')) {
    define('TOOLS_ROOT', dirname(dirname(__DIR__)));
}

require_once __DIR__ . '/Logging.php';

require_once TOOLS_ROOT . '/db_system.php';

require_once TOOLS_ROOT . '/src/Security/SecurityUtils.php';
require_once __DIR__ . '/Cache.php';
require_once TOOLS_ROOT . '/src/Views/jsonView.php';

SecurityUtils::setSecurityHeaders();

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Implement Global Rate Limiting
require_once TOOLS_ROOT . '/src/Security/RateLimiter.php';
$toolName = basename(dirname($_SERVER['SCRIPT_NAME']));
$rateLimiter = new \Security\RateLimiter($mysqli);
$cost = \Security\RateLimiter::getToolCost($toolName);

// Get client IP
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $clientIp = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
}
$clientIp = trim($clientIp);

// Skip rate limiting in CLI mode
if (php_sapi_name() !== 'cli') {
    $rateResult = $rateLimiter->consume($clientIp, $cost, $toolName);
    if (!$rateResult['allowed']) {
        header('HTTP/1.1 429 Too Many Requests');
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'Rate limit exceeded. You are making too many requests or running too many expensive scans. Please wait before trying again.',
            'remaining_tokens' => $rateResult['remaining']
        ]);
        exit();
    }

    // Inject remaining tokens into headers for UI
    header('X-RateLimit-Remaining: ' . $rateResult['remaining']);
}
?>