<?php
require_once __DIR__ . '/../Models/DnsLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Security/SecurityUtils.php';
class DnsLookupController {
    private $model;
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new DnsLookupModel($mysqli);
    }
    public function handleRequest($domain, $type = 'ANY', $ignoreCache = false) {
        $domain = trim($domain);
        if (empty($domain)) return ['query' => ['domain' => ''], 'response' => ['error' => 'Domain required.']];
        if (strpos($domain, '|') !== false) {
            list($domain, $t) = explode('|', $domain, 2);
            if ($type === 'ANY') $type = $t;
        }
        $domain = preg_replace('#^https?://#i', '', $domain);
        $domain = preg_replace('#/.*$#', '', $domain);
        $domain = rtrim($domain, '.');

        $sanitizedDomain = SecurityUtils::sanitizeInput($domain, 'domain', 255);
        if (!$sanitizedDomain) {
            return ['query' => ['tool' => 'dns-lookup', 'domain' => $domain, 'type' => $type], 'response' => ['error' => 'Invalid domain format.']];
        }
        $domain = $sanitizedDomain;

        $type = strtoupper(trim($type));
        $validTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'CAA', 'ANY'];
        if (!in_array($type, $validTypes)) $type = 'ANY';

        $tool = 'dns-lookup';
        DatabaseManager::logRequest($this->mysqli, $tool, $domain);
        $cacheInput = $domain . '|' . ($type ?: 'ANY');
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $cacheInput);
            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }
            if ($cache['status'] === 'stale') {
                if (DatabaseManager::markRefreshing($this->mysqli, $tool, $cacheInput)) {
                    // For DNS we pass the original input, which in queue daemon is passed to handleRequest($input, 'ANY', true)
                    // The queue daemon uses $cacheInput as $input, which is domain|type. We need to handle this!
                    // Wait, queue_daemon calls $controller->handleRequest($input, 'ANY', true); 
                    // This means if $input is "example.com|A", handleRequest receives ("example.com|A", "ANY"). 
                    // This is buggy in queue_daemon.
                    DatabaseManager::triggerBackgroundRefresh($tool, $cacheInput);
                }
                return $cache['data'];
            }
        }
        $result = $this->model->lookup($domain, $type);
        $data = ['query' => ['tool' => $tool, 'domain' => $domain, 'type' => $type], 'response' => $result];
        if (!isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $cacheInput, $data);
        return $data;
    }
}