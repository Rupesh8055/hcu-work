<?php
require_once __DIR__ . '/../Models/SpamDatabaseModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class SpamDatabaseController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new SpamDatabaseModel($mysqli);
    }

    public function handleRequest($host, $ignoreCache = false) {
        $host = trim($host);
        if (empty($host)) {
            return [
                'query' => ['tool' => 'spam-database', 'host' => ''],
                'response' => ['error' => 'Host parameter is required.']
            ];
        }

        $host = preg_replace('#^https?://#i', '', $host);
        $host = preg_replace('#/.*$#', '', $host);

        $sanitizedHost = SecurityUtils::sanitizeInput($host, 'string', 255);
        if (!$sanitizedHost) {
            return ['query' => ['tool' => 'spam-database', 'host' => $host], 'response' => ['error' => 'Invalid host format.']];
        }
        $host = $sanitizedHost;

        $tool = 'spam-database';

        DatabaseManager::logRequest($this->mysqli, $tool, $host);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $host);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $host)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $host);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->check($host);
        $data = [
            'query' => ['tool' => $tool, 'host' => $host],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $host, $data);
        }

        return $data;
    }
}