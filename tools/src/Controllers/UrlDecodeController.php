<?php
require_once __DIR__ . '/../Models/UrlDecodeModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';

class UrlDecodeController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new UrlDecodeModel($mysqli);
    }

    public function handleRequest($url, $ignoreCache = false) {
        $tool = 'url-decode';
        if (empty($url)) return ['query' => ['tool' => $tool, 'url' => ''], 'response' => ['error' => 'URL required.']];
        
        $sanitizedUrl = SecurityUtils::sanitizeInput($url, 'url', 8192); // URLs can be very long
        if (!$sanitizedUrl) {
             $sanitizedUrl = $url; // since it's just decoding, might not be a valid URL per se
        }
        $url = $sanitizedUrl;

        DatabaseManager::logRequest($this->mysqli, $tool, $url);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $url);
            if ($cache['status'] === 'hit') return $cache['data'];
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $url)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $url);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->decode($url);
        $data = ['query' => ['tool' => $tool, 'url' => $url], 'response' => $result];

        if (!isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $url, $data);
        return $data;
    }
}