<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/NameserverSitesController.php';
require_once __DIR__ . '/../views/jsonView.php';
$nameserver = isset($_GET['nameserver']) ? SecurityUtils::sanitizeInput(trim($_GET['nameserver']), 'domain', 255) : '';
$controller = new NameserverSitesController($mysqli);
$data = $controller->handleRequest($nameserver);
log_lookup($mysqli, 'nameserver-sites', $nameserver, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
