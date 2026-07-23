<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/IntelligenceGraphController.php';

$raw = $_GET['domain'] ?? $_GET['ip'] ?? $_GET['query'] ?? '';
$domainParam = trim($raw);

if ($domainParam !== '' && filter_var($domainParam, FILTER_VALIDATE_IP)) {
    $domain = SecurityUtils::sanitizeInput($domainParam, 'ip', 45);
} else {
    $domain = $domainParam !== '' ? SecurityUtils::sanitizeInput($domainParam, 'domain', 255) : '';
}

$controller = new IntelligenceGraphController($mysqli);
$data = $controller->handleRequest($domain);

renderJson($data);
