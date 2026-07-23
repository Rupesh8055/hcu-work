<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php'; 
require_once __DIR__ . '/../../src/Controllers/IpHistoryController.php'; 

$raw = $_GET['domain'] ?? $_GET['ip'] ?? $_GET['host'] ?? $_GET['query'] ?? ''; 
$domainParam = trim($raw); 
if ($domainParam !== '' && filter_var($domainParam, FILTER_VALIDATE_IP)) { 
    $domain = SecurityUtils::sanitizeInput($domainParam, 'ip', 45); 
} else { 
    $domain = $domainParam !== '' ? SecurityUtils::sanitizeInput($domainParam, 'domain', 255) : ''; 
} 

$limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
$offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;

$controller = new IpHistoryController($mysqli); 
$data = $controller->handleRequest($domain, $limit, $offset); 
log_lookup($mysqli, 'ip-history', $domain, !empty($data['response']['error']) ? $data['response']['error'] : null); 
renderJson($data);