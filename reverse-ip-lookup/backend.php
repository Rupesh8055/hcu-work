<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/ReverseIpLookupController.php';
require_once __DIR__ . '/../views/jsonView.php';
$ip = isset($_GET['ip']) ? SecurityUtils::sanitizeInput(trim($_GET['ip']), 'ip', 45) : '';
$controller = new ReverseIpLookupController($mysqli);
$data = $controller->handleRequest($ip);
log_lookup($mysqli, 'reverse-ip-lookup', $ip, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
