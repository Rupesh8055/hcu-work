<?php
require_once __DIR__ . '/../Models/AsnLookupModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
class AsnLookupController {
    private $model;
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new AsnLookupModel($mysqli);
    }
    public function handleRequest($asnQuery, $ignoreCache = false) {
        $asnQuery = trim($asnQuery);
        if (empty($asnQuery)) {
            return [
                'query' => ['tool' => 'asn-lookup', 'asn' => ''],
                'response' => ['error' => 'ASN query parameter is required.']
            ];
        }
        $originalQuery = $asnQuery;
        if (!ctype_digit($asnQuery) && !filter_var($asnQuery, FILTER_VALIDATE_IP) && filter_var($asnQuery, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $resolved = @gethostbyname($asnQuery);
            if ($resolved && $resolved !== $asnQuery) $asnQuery = $resolved;
        }
        $tool = 'asn-lookup';
        DatabaseManager::logRequest($this->mysqli, $tool, $asnQuery);
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $asnQuery);
            if ($cache['status'] === 'hit') return $cache['data'];
        }
        try {
            $result = $this->model->lookup($asnQuery);
            $data = [
                'query' => [
                    'tool' => $tool, 
                    'asn' => $originalQuery, 
                    'resolved' => $asnQuery !== $originalQuery ? $asnQuery : null
                ],
                'response' => $result
            ];
            if ($result && !isset($result['error'])) DatabaseManager::storeResult($this->mysqli, $tool, $asnQuery, $data);
            return $data;
        } catch (Exception $e) {
            return [
                'query' => ['tool' => $tool, 'asn' => $originalQuery],
                'response' => ['error' => 'Failed to process ASN lookup.']
            ];
        }
    }
}