<?php
require_once __DIR__ . '/../Models/MacLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
class MacLookupController {
    private $model;
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new MacLookupModel($mysqli);
    }
    public function handleRequest($mac, $ignoreCache = false) {
        $tool = 'mac-lookup';
        if (empty($mac)) return ['query' => ['tool' => $tool, 'mac' => ''], 'response' => ['error' => 'MAC required.']];
        
        $mac = strtoupper(trim($mac));
        if (!preg_match('/^([0-9A-F]{2}[:-]?){5}([0-9A-F]{2})$/', $mac) && 
            !preg_match('/^([0-9A-F]{4}\.){2}[0-9A-F]{4}$/', $mac) &&
            !preg_match('/^[0-9A-F]{12}$/', $mac)) {
            return ['query' => ['tool' => $tool, 'mac' => $mac], 'response' => ['error' => 'Invalid MAC address format.']];
        }

        DatabaseManager::logRequest($this->mysqli, $tool, $mac);
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $mac);
            if ($cache['status'] === 'hit') return $cache['data'];
        }
        $result = $this->model->lookupMac($mac);
        $data = ['query' => ['tool' => $tool, 'mac' => $mac], 'response' => $result];
        if (!isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $mac, $data);
        return $data;
    }
}