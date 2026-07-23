<?php
set_time_limit(8);
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';
SecurityUtils::setSecurityHeaders();
require_once __DIR__ . '/../controllers/SpamDatabaseController.php';
require_once __DIR__ . '/../views/jsonView.php';

$query = isset($_GET['query']) ? trim($_GET['query']) : '';
if (!$query) {
    $data = ['query' => ['tool' => 'spam-database', 'query' => ''], 'response' => ['error' => 'Query parameter is required.']];
    log_lookup($mysqli, 'spam-database', '', 'Query parameter is required.');
    renderJson($data);
    exit;
}

$controller = new SpamDatabaseController($mysqli);
$data = $controller->handleRequest($query);
$errorMessage = !empty($data['response']['error']) ? $data['response']['error'] : null;
log_lookup($mysqli, 'spam-database', $query, $errorMessage);
renderJson($data);
?>