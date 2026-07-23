<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/ReverseIpLookupController.php';

$raw = $_GET['ip'] ?? $_GET['host'] ?? $_GET['domain'] ?? $_GET['query'] ?? '';
$ip  = SecurityUtils::sanitizeInput(trim($raw), 'ip', 45);

$controller = new ReverseIpLookupController($mysqli);
$data = $controller->handleRequest($ip);

log_lookup($mysqli, 'reverse-ip-lookup', $ip, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);