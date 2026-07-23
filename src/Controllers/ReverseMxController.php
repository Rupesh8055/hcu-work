<?php
require_once __DIR__ . '/../Models/ReverseMxModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class ReverseMxController {
    private $model;
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new ReverseMxModel($mysqli);
    }

    public function handleRequest($mx, $ignoreCache = false) {
        $mx = trim($mx);
        if (empty($mx)) {
            return [
                'query' => ['tool' => 'reverse-mx-lookup', 'mx' => ''],
                'response' => ['error' => 'Mail server parameter is required.']
            ];
        }

        $mx = preg_replace('#^https?://#i', '', $mx);
        $mx = preg_replace('#/.*$#', '', $mx);
        $mx = rtrim($mx, '.');

        $sanitizedMx = SecurityUtils::sanitizeInput($mx, 'domain', 255);
        if (!$sanitizedMx) {
            return ['query' => ['tool' => 'reverse-mx-lookup', 'mx' => $mx], 'response' => ['error' => 'Invalid mail server format.']];
        }
        $mx = $sanitizedMx;

        $tool = 'reverse-mx-lookup';

        DatabaseManager::logRequest($this->mysqli, $tool, $mx);

        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $mx);

            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }

            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $mx)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $mx);
                }
                return $cache['data'];
            }
        }

        $result = $this->model->lookup($mx);
        $data = [
            'query' => ['tool' => $tool, 'mx' => $mx],
            'response' => $result
        ];

        if (!isset($result['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $mx, $data);
        }

        return $data;
    }
}