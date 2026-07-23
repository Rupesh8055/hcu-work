<?php
require_once __DIR__ . '/../Models/PortScannerModel.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class PortScannerController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new PortScannerModel($mysqli);
    }

    public function handleRequest($host, $ports = null, $ignoreCache = false) {
        $host = trim($host);
        if (empty($host)) {
            return [
                'query' => ['tool' => 'port-scanner', 'host' => ''],
                'response' => ['error' => 'Host is required.']
            ];
        }

        $sanitizedHost = SecurityUtils::sanitizeInput($host, 'domain', 255);
        if (!$sanitizedHost) {
            return [
                'query' => ['tool' => 'port-scanner', 'host' => $host],
                'response' => ['error' => 'Invalid host format provided.']
            ];
        }

        $sanitizedPorts = null;
        if (!empty($ports)) {
            $sanitizedPorts = SecurityUtils::sanitizeInput($ports, 'general', 1000);
        }

        $tool = 'port-scanner';
        
        $cacheKey = $sanitizedHost . ($sanitizedPorts ? '_' . md5($sanitizedPorts) : '');

        DatabaseManager::logRequest($this->mysqli, $tool, $cacheKey);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $cacheKey);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $cacheKey)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $cacheKey);
                }
                return $cache['data'];
            }
        }

        try {
            
            $result = $this->model->scan($sanitizedHost, $sanitizedPorts);
            $queryData = ['tool' => 'port-scanner', 'host' => $sanitizedHost];
            if ($sanitizedPorts) {
                $queryData['ports'] = $sanitizedPorts;
            }
            
            $data = [
                'query' => $queryData,
                'response' => $result
            ];

            if (!isset($result['error'])) {
                DatabaseManager::storeResult($this->mysqli, $tool, $cacheKey, $data);
            }

            return $data;
        } catch (Exception $e) {
            return [
                'query' => ['tool' => 'port-scanner', 'host' => $sanitizedHost],
                'response' => ['error' => 'An internal error occurred.']
            ];
        }
    }
}