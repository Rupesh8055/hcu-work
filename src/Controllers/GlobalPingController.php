<?php
require_once __DIR__ . '/../Models/GlobalPingModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class GlobalPingController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($host) {
        if (empty($host)) return ['error' => 'Host is required'];

        // Validate host is either a valid IP or a valid domain name
        if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^(?!:\/\/)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/', $host)) {
            return ['error' => 'Invalid host format. Please provide a valid IP address or domain name.'];
        }

        // 1. Check cache
        $cached = DatabaseManager::checkCache($this->mysqli, 'global-ping', $host);
        if ($cached['status'] === 'hit') return ['response' => $cached['data']];

        // 2. Fresh compute
        $model = new GlobalPingModel($this->mysqli);
        $data = $model->ping($host);

        // 3. Save to cache
        if ($data && !isset($data['error'])) {
            DatabaseManager::storeResult($this->mysqli, 'global-ping', $host, $data);
        }

        return ['response' => $data];
    }
}
?>