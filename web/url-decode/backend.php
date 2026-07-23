<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/UrlDecodeController.php';

$raw   = isset($_GET['input']) ? trim($_GET['input']) : (isset($_GET['url']) ? trim($_GET['url']) : '');
$input = $raw !== '' ? SecurityUtils::sanitizeInput($raw, 'general', 1000) : '';

$controller = new UrlDecodeController($mysqli);
$data = $controller->handleRequest($input);

log_lookup($mysqli, 'url-decode', $input, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);