<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/InvestigatorModeController.php';

$raw = $_GET['domain'] ?? $_GET['ip'] ?? $_GET['host'] ?? $_GET['query'] ?? $_GET['target'] ?? '';
$targetParam = trim($raw);

$controller = new InvestigatorModeController($mysqli);
$data = $controller->handleRequest($targetParam);

log_lookup($mysqli, 'investigator-mode', $targetParam, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
