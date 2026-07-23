<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/DnsPropagationController.php';
require_once __DIR__ . '/../views/jsonView.php';
$domain = isset($_GET['domain']) ? SecurityUtils::sanitizeInput(trim($_GET['domain']), 'domain', 255) : '';
$type = isset($_GET['type']) ? SecurityUtils::sanitizeInput(trim($_GET['type']), 'dns_type', 10) : 'A';
$controller = new DnsPropagationController($mysqli);
$data = $controller->handleRequest($domain, $type);
log_lookup($mysqli, 'dns-propagation', "{$domain} ({$type})", !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
