<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/PortScannerController.php';

$host  = isset($_GET['host']) ? SecurityUtils::sanitizeInput(trim($_GET['host']), 'general', 255) : '';
$ports = isset($_GET['ports']) ? SecurityUtils::sanitizeInput(trim($_GET['ports']), 'general', 1000) : null;

$controller = new PortScannerController($mysqli);
$data = $controller->handleRequest($host, $ports);

log_lookup($mysqli, 'port-scanner', $host, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);