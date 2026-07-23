<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/IranFirewallTestController.php';
require_once __DIR__ . '/../views/jsonView.php';
$url = isset($_GET['url']) ? SecurityUtils::sanitizeInput(trim($_GET['url']), FILTER_SANITIZE_URL) : '';
$controller = new IranFirewallTestController($mysqli);
$data = $controller->handleRequest($url);
log_lookup($mysqli, 'iran-firewall-test', $url, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
