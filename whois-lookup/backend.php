<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/WhoisLookupController.php';
require_once __DIR__ . '/../views/jsonView.php';
$domain = isset($_GET['domain']) ? SecurityUtils::sanitizeInput(trim($_GET['domain']), 'domain', 255) : '';

if (!$domain) {
    $data = ['query' => ['tool' => 'whois-lookup', 'domain' => ''], 'response' => ['error' => 'Invalid domain format provided.']];
    log_lookup($mysqli, 'whois-lookup', '', 'Invalid domain format provided.');
    renderJson($data);
    exit;
}
$controller = new WhoisLookupController($mysqli);
$data = $controller->handleRequest($domain);
log_lookup($mysqli, 'whois-lookup', $domain, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
