<?php

require_once __DIR__ . '/bootstrap.php';

class DatabaseCache {
    private static $expiry_days = 14;

    public static function get($mysqli, $tool, $input) {
        if (!$mysqli) return ['status' => 'miss', 'data' => null];

        $input_hash = md5(strtolower(trim($input)));
        $sql = "SELECT response, status, last_fetched FROM tool_cache WHERE tool = ? AND input_hash = ? LIMIT 1";
        $stmt = $mysqli->prepare($sql);
        
        if (!$stmt) return ['status' => 'miss', 'data' => null];

        $stmt->bind_param('ss', $tool, $input_hash);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if (!$row) return ['status' => 'miss', 'data' => null];

        $data = json_decode($row['response'], true);
        $last_fetched = $row['last_fetched'];
        $cache_status = $row['status'];

        $is_expired = (time() - strtotime($last_fetched)) > (self::$expiry_days * 86400);

        if ($is_expired || $cache_status === 'expired') {
            return [
                'status' => 'stale',
                'data' => $data,
                'last_fetched' => $last_fetched,
                'db_status' => $cache_status
            ];
        }

        return [
            'status' => 'hit',
            'data' => $data,
            'last_fetched' => $last_fetched,
            'db_status' => $cache_status
        ];
    }

    public static function set($mysqli, $tool, $input, $data, $status = 'valid') {
        if (!$mysqli) return false;

        $input_hash = md5(strtolower(trim($input)));
        $response_json = json_encode($data);
        $input_clean = trim($input);

        $sql = "INSERT INTO tool_cache (tool, input, input_hash, response, status, last_fetched) 
                VALUES (?, ?, ?, ?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE 
                response = VALUES(response), 
                status = VALUES(status), 
                last_fetched = NOW()";

        $stmt = $mysqli->prepare($sql);
        if (!$stmt) return false;

        $stmt->bind_param('sssss', $tool, $input_clean, $input_hash, $response_json, $status);
        $success = $stmt->execute();
        $stmt->close();

        return $success;
    }

    public static function markRefreshing($mysqli, $tool, $input) {
        if (!$mysqli) return false;
        $input_hash = md5(strtolower(trim($input)));
        $sql = "UPDATE tool_cache SET status = 'refreshing' WHERE tool = ? AND input_hash = ?";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) return false;
        $stmt->bind_param('ss', $tool, $input_hash);
        $success = $stmt->execute();
        $stmt->close();
        return $success;
    }

    public static function triggerBackgroundRefresh($tool, $input) {
        $phpPath = defined('PHP_BINARY') ? PHP_BINARY : 'php';
        $scriptPath = TOOLS_ROOT . '/src/Scripts/background_refresh.php';
        
        $argTool = escapeshellarg($tool);
        $argInput = escapeshellarg($input);

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            
            $cmd = "start /B $phpPath \"$scriptPath\" $argTool $argInput > NUL 2>&1";
            pclose(popen($cmd, "r"));
        } else {
            
            $cmd = "$phpPath \"$scriptPath\" $argTool $argInput > /dev/null 2>&1 &";
            exec($cmd);
        }
        return true;
    }
}
?>