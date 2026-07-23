<?php
require_once __DIR__ . '/../Models/ReverseNsLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class ReverseNsLookupController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($ns, $ignoreCache = false) {
        $ns = trim($ns);
        if (empty($ns)) return ['query' => ['ns' => ''], 'response' => ['error' => 'Nameserver is required.']];

        $ns = preg_replace('#^https?://#i', '', $ns);
        $ns = preg_replace('#/.*$#', '', $ns);
        $ns = rtrim($ns, '.');

        $sanitizedNs = SecurityUtils::sanitizeInput($ns, 'domain', 255);
        if (!$sanitizedNs) {
            return ['query' => ['tool' => 'reverse-ns', 'ns' => $ns], 'response' => ['error' => 'Invalid nameserver format.']];
        }
        $ns = $sanitizedNs;
        $tool = 'reverse-ns';

        DatabaseManager::logRequest($this->mysqli, $tool, $ns);

        // Check cache first
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $ns);
            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $ns)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $ns);
                }
                return $cache['data'];
            }
        }

        $model = new ReverseNsLookupModel($this->mysqli);
        $data = $model->lookup($ns);

        $result = ['query' => ['tool' => $tool, 'ns' => $ns], 'response' => $data];

        // Save to cache
        if (!isset($data['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $ns, $result);
        }

        return $result;
    }
}