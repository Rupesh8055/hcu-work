<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/DnsReportController.php';
require_once __DIR__ . '/../views/jsonView.php';
$domain = isset($_GET['domain']) ? SecurityUtils::sanitizeInput(trim($_GET['domain']), 'domain', 255) : '';
$controller = new DnsReportController($mysqli);
$data = $controller->handleRequest($domain);
log_lookup($mysqli, 'dns-report', $domain, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
