<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/HttpHeadersController.php';

$url = isset($_GET['url']) ? SecurityUtils::sanitizeInput(trim($_GET['url']), 'url', 255) : '';

$controller = new HttpHeadersController($mysqli);
$data = $controller->handleRequest($url);

log_lookup($mysqli, 'http-headers', $url, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);