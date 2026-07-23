<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/ReverseMxController.php';

$mxParam = $_GET['mx'] ?? $_GET['mailserver'] ?? $_GET['host'] ?? $_GET['domain'] ?? $_GET['query'] ?? '';
$mx      = trim($mxParam) !== '' ? SecurityUtils::sanitizeInput(trim($mxParam), 'domain', 255) : '';

$downloadParam = isset($_GET['download']) ? trim($_GET['download']) : '';
$download      = $downloadParam !== '' ? SecurityUtils::sanitizeInput(strtolower($downloadParam), 'general', 10) : '';

$controller = new ReverseMxController($mysqli);
$data = $controller->handleRequest($mx);

if ($download === 'csv' && empty($data['response']['error'])) {
    $domains = $data['response']['domains'] ?? [];
    $safeMx  = SecurityUtils::sanitizeOutput($mx ?: 'results');

    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="reverse-mx-' . $safeMx . '.csv"');

    $out = fopen('php://output', 'w');
    fputcsv($out, ['Mailserver', SecurityUtils::sanitizeOutput($mx)]);
    fputcsv($out, ['Domain Name']);
    foreach ($domains as $d) {
        fputcsv($out, [SecurityUtils::sanitizeOutput($d)]);
    }
    fclose($out);
    exit;
}

log_lookup($mysqli, 'reverse-mx-lookup', $mx, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);