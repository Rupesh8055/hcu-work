<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/ReverseNsLookupController.php';
require_once __DIR__ . '/../views/jsonView.php';
$ns = isset($_GET['ns']) ? SecurityUtils::sanitizeInput(trim($_GET['ns']), 'domain', 255) : '';
$controller = new ReverseNsLookupController($mysqli);
$data = $controller->handleRequest($ns);
log_lookup($mysqli, 'reverse-ns-lookup', $ns, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
