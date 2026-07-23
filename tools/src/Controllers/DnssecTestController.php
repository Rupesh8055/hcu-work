<?php
require_once __DIR__ . '/../Models/DnssecTestModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class DnssecTestController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new DnssecTestModel($mysqli);
    }

    public function handleRequest($domain, $ignoreCache = false) {
        $domain = trim($domain);
        if (empty($domain)) {
            return [
                'query' => ['tool' => 'dnssec-test', 'domain' => ''],
                'response' => ['error' => 'Domain parameter is required.']
            ];
        }

        $domain = preg_replace('#^https?://#i', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        $domain = rtrim($domain, '.');

        $sanitizedDomain = SecurityUtils::sanitizeInput($domain, 'domain', 255);
        if (!$sanitizedDomain) {
            return ['query' => ['tool' => 'dnssec-test', 'domain' => $domain], 'response' => ['error' => 'Invalid domain format.']];
        }
        $domain = $sanitizedDomain;

        $tool = 'dnssec-test';

        DatabaseManager::logRequest($this->mysqli, $tool, $domain);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $domain);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $domain)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $domain);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->test($domain);
        $data = [
            'query' => ['tool' => $tool, 'domain' => $domain],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $domain, $data);
        }

        return $data;
    }
}