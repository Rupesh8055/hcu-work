<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';
require_once __DIR__ . '/../controllers/SiteDownCheckerController.php';
require_once __DIR__ . '/../views/jsonView.php';

SecurityUtils::setSecurityHeaders();

$rawUrl = isset($_GET['url']) ? trim($_GET['url']) : '';

if (!$rawUrl) {
    $data = ['query' => ['tool' => 'site-down-checker', 'url' => ''], 'response' => ['error' => 'URL parameter is required.']];
    log_lookup($mysqli, 'site-down-checker', '', 'URL parameter is required.');
    renderJson($data);
    exit;
}

$controller = new SiteDownCheckerController($mysqli);
$data = $controller->handleRequest($rawUrl);

$errorMessage = !empty($data['response']['error']) ? $data['response']['error'] : null;
log_lookup($mysqli, 'site-down-checker', $rawUrl, $errorMessage);

renderJson($data);
?>