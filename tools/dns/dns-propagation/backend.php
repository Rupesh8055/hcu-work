<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/DnsPropagationController.php';

$domain = isset($_GET['domain']) ? SecurityUtils::sanitizeInput(trim($_GET['domain']), 'domain', 255) : '';
$type   = isset($_GET['type']) ? SecurityUtils::sanitizeInput(trim($_GET['type']), 'dns_type', 10) : 'A';

$controller = new DnsPropagationController($mysqli);
$data = $controller->handleRequest($domain, $type);

log_lookup($mysqli, 'dns-propagation', $domain, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);