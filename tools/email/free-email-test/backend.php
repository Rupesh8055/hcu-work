<?php
require_once __DIR__ . '/../../src/Includes/bootstrap.php';
require_once __DIR__ . '/../../src/Controllers/FreeEmailTestController.php';

$email = isset($_GET['email']) ? SecurityUtils::sanitizeInput(trim($_GET['email']), 'email', 255) : '';

$controller = new FreeEmailTestController($mysqli);
$data = $controller->handleRequest($email);

log_lookup($mysqli, 'free-email-test', $email, !empty($data['response']['error']) ? $data['response']['error'] : null);
renderJson($data);