<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/DnssecTestController.php';

$domain = isset($_GET['domain']) ? SecurityUtils::sanitizeInput(trim($_GET['domain']), 'domain', 255) : '';

$controller = new DnssecTestController($mysqli);
$data = $controller->handleRequest($domain);

log_lookup($mysqli, 'dnssec-test', $domain, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);