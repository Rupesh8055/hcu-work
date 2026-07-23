<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/TracerouteController.php';

$raw  = $_GET['host'] ?? $_GET['domain'] ?? $_GET['ip'] ?? $_GET['query'] ?? '';
$host = SecurityUtils::sanitizeInput(trim($raw), 'general', 255);

$controller = new TracerouteController($mysqli);
$data = $controller->handleRequest($host);

log_lookup($mysqli, 'traceroute', $host, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);