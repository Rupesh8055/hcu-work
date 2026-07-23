<?php
require_once __DIR__ . '/../Models/FreeEmailTestModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';

class FreeEmailTestController {
    private $model;
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new FreeEmailTestModel($mysqli);
    }
    public function handleRequest($email, $ignoreCache = false) {
        $tool = 'free-email-test';
        $email = trim($email);
        if (empty($email)) return ['query' => ['tool' => $tool, 'email' => ''], 'response' => ['error' => 'Email required.']];

        $sanitizedEmail = SecurityUtils::sanitizeInput($email, 'email', 255);
        if (!$sanitizedEmail) {
            return ['query' => ['tool' => $tool, 'email' => $email], 'response' => ['error' => 'Invalid email format.']];
        }
        $email = $sanitizedEmail;

        DatabaseManager::logRequest($this->mysqli, $tool, $email);
        
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $email);
            if ($cache['status'] === 'hit') return $cache['data'];
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $email)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $email);
                }
                return $cache['data'];
            }
        }
        
        $result = $this->model->test($email);
        $data = ['query' => ['tool' => $tool, 'email' => $email], 'response' => $result];
        
        if (!isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $email, $data);
        
        return $data;
    }
}