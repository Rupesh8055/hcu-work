<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/IpHistoryController.php';
require_once __DIR__ . '/../views/jsonView.php';
$query = isset($_GET['query']) ? SecurityUtils::sanitizeInput(trim($_GET['query']), 'general', 255) : '';
$controller = new IpHistoryController($mysqli);
$data = $controller->handleRequest($query);
log_lookup($mysqli, 'ip-history', $query, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
