<?php
require_once __DIR__ . '/../Models/ReverseIpLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class ReverseIpLookupController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new ReverseIpLookupModel($mysqli);
    }

    public function handleRequest($host, $ignoreCache = false) {
        $host = trim($host);
        if (empty($host)) {
            return [
                'query' => ['tool' => 'reverse-ip-lookup', 'host' => ''],
                'response' => ['error' => 'Host parameter is required.']
            ];
        }

        $ip = $host;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            // It might be a domain
            $sanitizedDomain = SecurityUtils::sanitizeInput($host, 'domain', 255);
            if (!$sanitizedDomain) {
                return ['query' => ['tool' => 'reverse-ip-lookup', 'host' => $host], 'response' => ['error' => 'Invalid IP address or domain format.']];
            }
            $resolved = gethostbyname($sanitizedDomain);
            if ($resolved === $sanitizedDomain) {
                return ['query' => ['tool' => 'reverse-ip-lookup', 'host' => $host], 'response' => ['error' => 'Could not resolve domain to an IP address.']];
            }
            $ip = $resolved;
        }

        $tool = 'reverse-ip-lookup';

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
            'query' => ['tool' => $tool, 'host' => $host],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $ip, $data);
        }

        return $data;
    }
}