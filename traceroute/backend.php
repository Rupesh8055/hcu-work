<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/TracerouteController.php';
require_once __DIR__ . '/../views/jsonView.php';
$host = isset($_GET['host']) ? SecurityUtils::sanitizeInput(trim($_GET['host']), 'domain', 255) : '';
$controller = new TracerouteController($mysqli);
$data = $controller->handleRequest($host);
log_lookup($mysqli, 'traceroute', $host, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
