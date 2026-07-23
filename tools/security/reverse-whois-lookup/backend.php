<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/ReverseWhoisLookupController.php';

$raw   = $_GET['query'] ?? $_GET['domain'] ?? $_GET['host'] ?? $_GET['email'] ?? '';
$query = SecurityUtils::sanitizeInput(trim($raw), 'general', 255);

$controller = new ReverseWhoisLookupController($mysqli);
$data = $controller->handleRequest($query);

log_lookup($mysqli, 'reverse-whois-lookup', $query, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);