<?php
require_once __DIR__ . '/../Models/AbuseLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';
class AbuseLookupController {
    private $model;
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new AbuseLookupModel($mysqli);
    }
    public function handleRequest($query, $ignoreCache = false) {
        $tool = 'abuse-lookup';
        $query = trim($query);
        if (empty($query)) return ['query' => ['tool' => $tool, 'input' => ''], 'response' => ['error' => 'Query required.']];

        $sanitizedQuery = SecurityUtils::sanitizeInput($query, 'string', 255);
        if (!$sanitizedQuery) {
            return ['query' => ['tool' => $tool, 'input' => $query], 'response' => ['error' => 'Invalid query format.']];
        }
        $query = $sanitizedQuery;

        DatabaseManager::logRequest($this->mysqli, $tool, $query);
        
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $query);
            if ($cache['status'] === 'hit') return $cache['data'];
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $query)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $query);
                }
                return $cache['data'];
            }
        }
        
        $result = $this->model->lookup($query);
        $data = ['query' => ['tool' => $tool, 'input' => $query], 'response' => $result];
        
        if (!isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $query, $data);
        
        return $data;
    }
}