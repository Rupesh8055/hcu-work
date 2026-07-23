<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/GlobalPingController.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    renderJson(['error' => 'Method Not Allowed']);
    exit;
}

$host = isset($_GET['host']) ? SecurityUtils::sanitizeInput(trim($_GET['host']), 'general', 255) : '';

$controller = new GlobalPingController($mysqli);
$data = $controller->handleRequest($host);

log_lookup($mysqli, 'global-ping', $host, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);