<?php
require_once __DIR__ . '/../Models/DnsReportModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

require_once __DIR__ . '/../Security/SecurityUtils.php';

class DnsReportController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($domain, $ignoreCache = false) {
        $domain = trim($domain);
        if (empty($domain)) return ['query' => ['domain' => ''], 'response' => ['error' => 'Domain is required.']];

        $domain = preg_replace('#^https?://#i', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        $domain = rtrim($domain, '.');

        $sanitizedDomain = SecurityUtils::sanitizeInput($domain, 'domain', 255);
        if (!$sanitizedDomain) {
            return ['query' => ['tool' => 'dns-report', 'domain' => $domain], 'response' => ['error' => 'Invalid domain format.']];
        }
        $domain = $sanitizedDomain;
        $tool = 'dns-report';

        DatabaseManager::logRequest($this->mysqli, $tool, $domain);

        // Check Cache
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $domain);
            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $domain)) {
                    DatabaseManager::triggerBackgroundRefresh($tool, $domain);
                }
                return $cache['data'];
            }
        }

        $model = new DnsReportModel($this->mysqli);
        $data = $model->getReport($domain);

        $result = ['query' => ['tool' => $tool, 'domain' => $domain], 'response' => $data];

        // Save to Cache
        if (!isset($data['error'])) {
            DatabaseManager::storeResult($this->mysqli, $tool, $domain, $result);
        }

        return $result;
    }
}