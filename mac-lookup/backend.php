<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/MacLookupController.php';
require_once __DIR__ . '/../views/jsonView.php';
$mac = isset($_GET['mac']) ? SecurityUtils::sanitizeInput(trim($_GET['mac']), 'mac', 17) : '';
$controller = new MacLookupController($mysqli);
$data = $controller->handleRequest($mac);
log_lookup($mysqli, 'mac-lookup', $mac, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
