<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/AbuseLookupController.php';

$raw   = $_GET['query'] ?? $_GET['domain'] ?? $_GET['ip'] ?? $_GET['host'] ?? '';
$query = SecurityUtils::sanitizeInput(trim($raw), 'general', 255);

$controller = new AbuseLookupController($mysqli);
$data = $controller->handleRequest($query);

log_lookup($mysqli, 'abuse-lookup', $query, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);