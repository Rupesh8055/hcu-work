<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/ChineseFirewallTestController.php';
require_once __DIR__ . '/../views/jsonView.php';
$url = isset($_GET['url']) ? SecurityUtils::sanitizeInput(trim($_GET['url']), FILTER_SANITIZE_URL) : '';
$controller = new ChineseFirewallTestController($mysqli);
$data = $controller->handleRequest($url);
log_lookup($mysqli, 'chinese-firewall-test', $url, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
