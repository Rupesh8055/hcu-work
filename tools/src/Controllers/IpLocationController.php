<?php
require_once __DIR__ . '/../Models/IpLocationModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class IpLocationController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new IpLocationModel($mysqli);
    }

    public function handleRequest($ip, $ignoreCache = false) {
        if (empty($ip)) {
            return [
                'query' => ['tool' => 'ip-location', 'ip' => ''],
                'response' => ['error' => 'IP parameter is required.']
            ];
        }

        $ip = strtolower(trim($ip));
        if (!filter_var($ip, FILTER_VALIDATE_IP) && !preg_match('/^(?!:\/\/)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/', $ip)) {
            return [
                'query' => ['tool' => 'ip-location', 'ip' => $ip],
                'response' => ['error' => 'Invalid target format. Please provide a valid IP address or domain name.']
            ];
        }

        $tool = 'ip-location';

        DatabaseManager::logRequest($this->mysqli, $tool, $ip);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $ip);

            if ($cache['status'] === 'hit') {
                $loc = $cache['data']['response']['location'] ?? [];
                $lat = $loc['latitude'] ?? '0';
                $lon = $loc['longitude'] ?? '0';
                if ($lat !== '0' || $lon !== '0') {
                    return $cache['data'];
                }
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $ip)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $ip);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->locate($ip);
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