<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/ReverseMxController.php';
require_once __DIR__ . '/../views/jsonView.php';
$mx = isset($_GET['mx']) ? SecurityUtils::sanitizeInput(trim($_GET['mx']), 'domain', 255) : '';

log_lookup($mysqli, 'reverse-mx-lookup', $mx, 'DEBUG: Script started, mx=' . $mx);
$controller = new ReverseMxController($mysqli);
$data = $controller->handleRequest($mx);
log_lookup($mysqli, 'reverse-mx-lookup', $mx, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);