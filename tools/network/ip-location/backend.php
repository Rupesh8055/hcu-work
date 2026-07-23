<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/IpLocationController.php';

$raw = $_GET['ip'] ?? $_GET['host'] ?? $_GET['domain'] ?? $_GET['query'] ?? '';
$ip  = SecurityUtils::sanitizeInput(trim($raw), 'ip', 45);

$controller = new IpLocationController($mysqli);
$data = $controller->handleRequest($ip);

log_lookup($mysqli, 'ip-location', $ip, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);