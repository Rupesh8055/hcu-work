<?php
require_once __DIR__ . '/../Models/ReverseDnsModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class ReverseDnsController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new ReverseDnsModel($mysqli);
    }

    public function handleRequest($ip, $ignoreCache = false) {
        $ip = trim($ip);
        if (empty($ip)) {
            return [
                'query' => ['tool' => 'reverse-dns', 'ip' => ''],
                'response' => ['error' => 'IP parameter is required.']
            ];
        }

        $sanitizedIp = SecurityUtils::sanitizeInput($ip, 'ip');
        if (!$sanitizedIp) {
            return ['query' => ['tool' => 'reverse-dns', 'ip' => $ip], 'response' => ['error' => 'Invalid IP address format.']];
        }
        $ip = $sanitizedIp;

        $tool = 'reverse-dns';

        DatabaseManager::logRequest($this->mysqli, $tool, $ip);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $ip);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $ip)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $ip);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->lookup($ip);
        $data = [
            'query' => ['tool' => $tool, 'ip' => $ip],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $ip, $data);
        }

        return $data;
    }
}