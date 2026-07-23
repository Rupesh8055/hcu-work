<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/ReverseWhoisLookupController.php';
require_once __DIR__ . '/../views/jsonView.php';
$query = isset($_GET['query']) ? SecurityUtils::sanitizeInput(trim($_GET['query']), 'general', 255) : '';
$type = isset($_GET['type']) ? SecurityUtils::sanitizeInput(trim($_GET['type']), 'dns_type', 10) : 'registrant';
$controller = new ReverseWhoisLookupController($mysqli);
$data = $controller->handleRequest($query, $type);
log_lookup($mysqli, 'reverse-whois-lookup', "{$query} ({$type})", !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
