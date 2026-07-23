<?php
require_once __DIR__ . '/../Models/DnsPropagationModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class DnsPropagationController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($domain, $recordType = 'A', $ignoreCache = false) {
        $domain = trim($domain);
        if (empty($domain)) return ['query' => ['domain' => ''], 'response' => ['error' => 'Domain is required.']];
        
        $domain = preg_replace('#^https?://#i', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        $domain = rtrim($domain, '.');

        $sanitizedDomain = SecurityUtils::sanitizeInput($domain, 'domain', 255);
        if (!$sanitizedDomain) {
            return ['query' => ['tool' => 'dns-propagation', 'domain' => $domain, 'type' => $recordType], 'response' => ['error' => 'Invalid domain format.']];
        }
        $domain = $sanitizedDomain;

        $recordType = strtoupper(trim($recordType));
        $validTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME'];
        if (!in_array($recordType, $validTypes)) $recordType = 'A';

        $tool = 'dns-propagation';
        $cacheKey = $domain . '|' . $recordType;

        DatabaseManager::logRequest($this->mysqli, $tool, $domain);

        // Check Cache
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

        $model = new DnsPropagationModel($this->mysqli);
        $data = $model->check($domain, $recordType);

        $result = ['query' => ['tool' => $tool, 'domain' => $domain, 'type' => $recordType], 'response' => $data];

        // Save to Cache
        if (!isset($data['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $cacheKey, $result);
        }

        return $result;
    }
}