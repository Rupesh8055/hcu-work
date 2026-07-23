<?php
require_once __DIR__ . '/../Models/TracerouteModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';

class TracerouteController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($host) {
        $host = trim($host);
        if (empty($host)) {
            return [
                'query' => ['tool' => 'traceroute', 'host' => ''],
                'response' => ['error' => 'Host parameter is required.']
            ];
        }

        $sanitizedHost = SecurityUtils::sanitizeInput($host, 'domain', 255);
        if (!$sanitizedHost) {
            $sanitizedHost = SecurityUtils::sanitizeInput($host, 'ip', 45);
        }
        if (!$sanitizedHost) {
            return [
                'query' => ['tool' => 'traceroute', 'host' => $host],
                'response' => ['error' => 'Invalid host format provided.']
            ];
        }

        $tool = 'traceroute';

        DatabaseManager::logRequest($this->mysqli, $tool, $sanitizedHost);

        // 1. Check cache
        $cached = DatabaseManager::checkCache($this->mysqli, $tool, $sanitizedHost);
        if ($cached['status'] === 'hit') return $cached['data'];

        // 2. Fresh compute
        $model = new TracerouteModel($this->mysqli);
        $result = $model->trace($sanitizedHost);

        $data = [
            'query' => ['tool' => $tool, 'host' => $sanitizedHost],
            'response' => $result
        ];

        // 3. Save to cache
        if (!isset($result['error']) && (!isset($result['status']) || $result['status'] !== 'error')) {
            DatabaseManager::storeResult($this->mysqli, $tool, $sanitizedHost, $data);
        }

        return $data;
    }
}
?>