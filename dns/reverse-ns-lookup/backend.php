<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/ReverseNsLookupController.php';

$raw = $_GET['nameserver'] ?? $_GET['ns'] ?? $_GET['domain'] ?? $_GET['host'] ?? $_GET['query'] ?? '';
$nameserver = SecurityUtils::sanitizeInput(trim($raw), 'domain', 255);

$controller = new ReverseNsLookupController($mysqli);
$data = $controller->handleRequest($nameserver);

log_lookup($mysqli, 'reverse-ns-lookup', $nameserver, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);