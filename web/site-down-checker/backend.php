<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/SiteDownCheckerController.php';

$rawUrl = isset($_GET['url']) ? trim($_GET['url']) : '';
if ($rawUrl !== '' && !preg_match('/^https?:\/\//i', $rawUrl)) {
    $rawUrl = 'https://' . $rawUrl;
}

$url = $rawUrl !== '' ? SecurityUtils::sanitizeInput($rawUrl, 'url', 2048) : '';

if (!$url) {
    $data = [
        'query'    => ['tool' => 'site-down-checker', 'url' => ''],
        'response' => ['error' => 'URL parameter is required.']
    ];
    log_lookup($mysqli, 'site-down-checker', '', 'URL parameter is required.');
    renderJson($data);
    exit;
}

$controller = new SiteDownCheckerController($mysqli);
$data = $controller->handleRequest($url);

log_lookup($mysqli, 'site-down-checker', $url, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);