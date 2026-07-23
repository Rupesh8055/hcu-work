<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/UrlDecodeController.php';
require_once __DIR__ . '/../views/jsonView.php';
$url = isset($_GET['url']) ? SecurityUtils::sanitizeInput(trim($_GET['url']), FILTER_SANITIZE_URL) : '';
$controller = new UrlDecodeController($mysqli);
$data = $controller->handleRequest($url);
log_lookup($mysqli, 'url-decode', $url, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
