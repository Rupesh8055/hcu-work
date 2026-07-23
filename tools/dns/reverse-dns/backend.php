<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/ReverseDnsController.php';

$raw = $_GET['ip'] ?? $_GET['host'] ?? $_GET['domain'] ?? $_GET['query'] ?? '';
$ip  = SecurityUtils::sanitizeInput(trim($raw), 'string', 255);

if (!$ip) {
    echo json_encode(['error' => 'IP or Hostname is required.']);
    exit;
}

$controller = new ReverseDnsController($mysqli);
$data = $controller->handleRequest($ip);

log_lookup($mysqli, 'reverse-dns', $ip, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);