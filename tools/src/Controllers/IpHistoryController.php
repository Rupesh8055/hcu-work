<?php
require_once __DIR__ . '/../Models/IpHistoryModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class IpHistoryController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($query, $limit = 50, $offset = 0) {
        if (empty($query)) return ['error' => 'Domain or IP address is required.'];
        
        $query = strtolower(trim($query));
        
        if (!filter_var($query, FILTER_VALIDATE_IP) && !preg_match('/^(?!:\/\/)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/', $query)) {
            return ['error' => 'Invalid target format. Please provide a valid IP address or domain name.'];
        }

        DatabaseManager::logRequest($this->mysqli, 'ip-history', $query);

        $model = new IpHistoryModel($this->mysqli);
        
        // Cache mechanism is disabled for now since data is highly dynamic and depends on offset/limit
        // Or we cache based on query, limit, and offset
        $cacheKey = $query . '_l' . $limit . '_o' . $offset;
        $cache = DatabaseManager::checkCache($this->mysqli, 'ip-history', $cacheKey);
        if ($cache['status'] === 'hit') {
            return ['response' => $cache['data'], 'cached' => true];
        }

        $data = $model->getHistory($query, $limit, $offset);
        $totalCount = $model->getHistoryCount($query);

        if (isset($data['error'])) {
            return ['error' => 'System error: ' . $data['error']];
        }

        $responseObj = [];
        if (empty($data)) {
            $responseObj = [
                'message' => 'No historical data found for this entry yet. Data is collected progressively as domains are scanned.',
                'history' => [],
                'count' => 0,
                'total_observed' => 0
            ];
        } else {
            // Find overall first and latest seen
            $first_seen_overall = $data[0]['first_seen'] ?? null;
            $latest_seen_overall = $data[0]['last_seen'] ?? null;

            if ($this->mysqli) {
                // Get the absolute minimum first_seen and absolute maximum last_seen across ALL records
                $isIp = filter_var($query, FILTER_VALIDATE_IP);
                $qType = $isIp ? 'ip_address' : 'domain';
                $stmt = $this->mysqli->prepare("SELECT MIN(first_seen), MAX(last_seen) FROM ip_history WHERE $qType = ?");
                if ($stmt) {
                    $stmt->bind_param('s', $query);
                    $stmt->execute();
                    $stmt->bind_result($minFs, $maxLs);
                    if ($stmt->fetch()) {
                        if ($minFs) $first_seen_overall = date('Y-m-d H:i:s', strtotime($minFs));
                        if ($maxLs) $latest_seen_overall = date('Y-m-d H:i:s', strtotime($maxLs));
                    }
                    $stmt->close();
                }
            }

            $responseObj = [
                'history' => $data,
                'count' => count($data),
                'total_observed' => $totalCount,
                'first_seen_overall' => $first_seen_overall,
                'latest_seen_overall' => $latest_seen_overall
            ];
        }

        DatabaseManager::storeResult($this->mysqli, 'ip-history', $cacheKey, $responseObj);

        return ['response' => $responseObj, 'cached' => false];
    }
}