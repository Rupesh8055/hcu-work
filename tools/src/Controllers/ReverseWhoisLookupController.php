<?php
require_once __DIR__ . '/../Models/ReverseWhoisLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class ReverseWhoisLookupController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new ReverseWhoisLookupModel($mysqli);
    }

    public function handleRequest($query, $ignoreCache = false) {
        $query = trim($query);
        if (empty($query)) {
            return [
                'query' => ['tool' => 'reverse-whois-lookup', 'query' => ''],
                'response' => ['error' => 'Query parameter is required.']
            ];
        }

        $sanitizedQuery = SecurityUtils::sanitizeInput($query, 'string', 255);
        if (!$sanitizedQuery) {
            return ['query' => ['tool' => 'reverse-whois-lookup', 'query' => $query], 'response' => ['error' => 'Invalid query format.']];
        }
        $query = $sanitizedQuery;

        $tool = 'reverse-whois-lookup';

        DatabaseManager::logRequest($this->mysqli, $tool, $query);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $query);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $query)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $query);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->lookup($query);
        $data = [
            'query' => ['tool' => $tool, 'query' => $query],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $query, $data);
        }

        return $data;
    }
}