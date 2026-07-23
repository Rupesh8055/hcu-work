<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/PortScannerController.php';
require_once __DIR__ . '/../views/jsonView.php';

$host = isset($_GET['host']) ? trim($_GET['host']) : '';

if (!$host) {
    $data = ['query' => ['tool' => 'port-scanner', 'host' => ''], 'response' => ['error' => 'Host parameter is required.']];
    log_lookup($mysqli, 'port-scanner', '', 'Host parameter is required.');
    renderJson($data);
    exit;
}

$controller = new PortScannerController($mysqli);
$data = $controller->handleRequest($host);

$errorMessage = !empty($data['response']['error']) ? $data['response']['error'] : null;
log_lookup($mysqli, 'port-scanner', $host, $errorMessage);

renderJson($data);
?> 