<?php
require_once __DIR__ . '/../Models/SiteDownCheckerModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class SiteDownCheckerController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new SiteDownCheckerModel($mysqli);
    }

    public function handleRequest($url, $ignoreCache = false) {
        $url = trim($url);
        if (empty($url)) {
            return [
                'query' => ['tool' => 'site-down-checker', 'url' => ''],
                'response' => ['error' => 'URL parameter is required.']
            ];
        }

        if (!preg_match('#^https?://#i', $url)) {
            $url = 'http://' . $url;
        }

        $sanitizedUrl = SecurityUtils::sanitizeInput($url, 'url', 2048);
        if (!$sanitizedUrl || !filter_var($sanitizedUrl, FILTER_VALIDATE_URL)) {
            return ['query' => ['tool' => 'site-down-checker', 'url' => $url], 'response' => ['error' => 'Invalid URL format.']];
        }
        $url = $sanitizedUrl;

        $tool = 'site-down-checker';

        DatabaseManager::logRequest($this->mysqli, $tool, $url);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $url);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $url)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $url);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->check($url);
        $data = [
            'query' => ['tool' => $tool, 'url' => $url],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $url, $data);
        }

        return $data;
    }
}