<?php
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../security/SecurityUtils.php';

SecurityUtils::setSecurityHeaders();

require_once __DIR__ . '/../controllers/FreeEmailTestController.php';
require_once __DIR__ . '/../views/jsonView.php';
$email = isset($_GET['email']) ? SecurityUtils::sanitizeInput(trim($_GET['email']), FILTER_SANITIZE_EMAIL) : '';
$controller = new FreeEmailTestController($mysqli);
$data = $controller->handleRequest($email);
log_lookup($mysqli, 'free-email-test', $email, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);
