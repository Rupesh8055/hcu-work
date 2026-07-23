<?php
require_once __DIR__ . '/../Models/HttpHeadersModel.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class HttpHeadersController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new HttpHeadersModel($mysqli);
    }

    public function handleRequest($url, $ignoreCache = false) {
        $tool = 'http-headers';
        $url = trim($url);

        if (empty($url)) {
            return [
                'query' => ['tool' => $tool, 'url' => ''],
                'response' => ['error' => 'URL is required.']
            ];
        }

        if (!preg_match('#^https?://#i', $url)) {
            $url = 'http://' . $url;
        }

        $sanitizedUrl = SecurityUtils::sanitizeInput($url, 'url', 2048);
        if (!$sanitizedUrl || !filter_var($sanitizedUrl, FILTER_VALIDATE_URL)) {
            return ['query' => ['tool' => $tool, 'url' => $url], 'response' => ['error' => 'Invalid URL format.']];
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

        $res = $this->model->getHeaders($url);
        $data = ['query' => ['tool' => $tool, 'url' => $url], 'response' => $res];

        if (!isset($res['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $url, $data);
        return $data;
    }
}