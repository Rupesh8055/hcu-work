<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/AsnLookupController.php';

$raw = $_GET['asn'] ?? $_GET['query'] ?? $_GET['ip'] ?? $_GET['host'] ?? $_GET['domain'] ?? '';
$asnQuery = SecurityUtils::sanitizeInput($raw, 'string', 255);
if (!$asnQuery) {
    renderJson(['error' => 'ASN, IP, or Domain is required.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    renderJson(['error' => 'Method Not Allowed']);
    exit;
}

$controller = new AsnLookupController($mysqli);
$data = $controller->handleRequest($asnQuery);
log_lookup($mysqli, 'asn-lookup', $asnQuery, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);