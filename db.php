<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

define('DB_HOST', 'tools.cyberjagrithi.com:3306');
define('DB_USER', 'u406753664_test_user');
define('DB_PASSWORD', 'Cyber@3344');
define('DB_NAME', 'u406753664_tools_test');

if (!is_dir(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

    if ($mysqli->connect_errno) {
        error_log("Database connection failed: " . $mysqli->connect_error);
        $mysqli = null;
    } else {
        $mysqli->set_charset("utf8mb4");
        $mysqli->query("SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
    }

} catch (Exception $e) {
    error_log("Database connection exception: " . $e->getMessage());
    $mysqli = null;
}

function log_lookup($mysqli, $tool, $input, $errorMessage = null) {
    if (!$mysqli || $mysqli->connect_errno) {
        log_lookup_local($tool, $input, $errorMessage);
        return;
    }

    try {
        require_once __DIR__ . '/security/SecurityUtils.php';
        
        $tool = SecurityUtils::sanitizeSQL(is_string($tool) ? substr(trim($tool), 0, 100) : '');
        $input = SecurityUtils::sanitizeSQL(is_string($input) ? substr(trim($input), 0, 1000) : '');
        $errorMessage = SecurityUtils::sanitizeSQL(is_string($errorMessage) ? substr(trim($errorMessage), 0, 500) : null);

        $result = $mysqli->query("SHOW COLUMNS FROM lookup_logs LIKE 'ip_address'");
        if ($result->num_rows > 0) {
            $stmt = $mysqli->prepare("INSERT INTO lookup_logs (tool, input, error_message, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?, NOW())");
            if ($stmt) {
                $ip = SecurityUtils::getClientIP();
                $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
                $stmt->bind_param('sssss', $tool, $input, $errorMessage, $ip, $userAgent);
                $stmt->execute();
                $stmt->close();
            }
        } else {
            $stmt = $mysqli->prepare("INSERT INTO lookup_logs (tool, input, error_message, created_at) VALUES (?, ?, ?, NOW())");
            if ($stmt) {
                $stmt->bind_param('sss', $tool, $input, $errorMessage);
                $stmt->execute();
                $stmt->close();
            }
        }
    } catch (Exception $e) {
        log_lookup_local($tool, $input, $errorMessage);
        error_log("Database logging error: " . $e->getMessage());
    }
}

function log_lookup_local($tool, $input, $errorMessage = null) {
    $logFile = __DIR__ . '/logs/lookup_logs.txt';

    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'Unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    if ($errorMessage) {
        if (strpos($errorMessage, 'DEBUG:') === 0) {
            $status = 'DEBUG';
            $message = $errorMessage;
        } else {
            $status = 'ERROR';
            $message = $errorMessage;
        }
    } else {
        $status = 'SUCCESS';
        $message = 'Query completed successfully';
    }

    $entry = sprintf(
        "[%s] %s: %s | %s | %s | %s | %s -> %s\n",
        $timestamp,
        strtoupper($tool),
        htmlspecialchars($input, ENT_QUOTES, 'UTF-8'),
        htmlspecialchars($ip, ENT_QUOTES, 'UTF-8'),
        htmlspecialchars($method, ENT_QUOTES, 'UTF-8'),
        htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8'),
        $status,
        htmlspecialchars($message, ENT_QUOTES, 'UTF-8')
    );

    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

function is_ip_blocked($mysqli, $ip) {
    if (!$mysqli || $mysqli->connect_errno) {
        return false;
    }

    try {
        require_once __DIR__ . '/security/SecurityUtils.php';
        $ip = SecurityUtils::sanitizeSQL($ip);
        
        $stmt = $mysqli->prepare("SELECT blocked_until FROM ip_blocks WHERE ip_address = ? AND (blocked_until IS NULL OR blocked_until > NOW())");
        if ($stmt) {
            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $result = $stmt->get_result();
            $blocked = $result->num_rows > 0;
            $stmt->close();
            return $blocked;
        }
    } catch (Exception $e) {
        error_log("IP block check error: " . $e->getMessage());
    }
    
    return false;
}

function block_ip($mysqli, $ip, $reason = '', $duration = null) {
    if (!$mysqli || $mysqli->connect_errno) {
        return false;
    }

    try {
        require_once __DIR__ . '/security/SecurityUtils.php';
        $ip = SecurityUtils::sanitizeSQL($ip);
        $reason = SecurityUtils::sanitizeSQL($reason);
        
        $blockedUntil = null;
        if ($duration) {
            $blockedUntil = date('Y-m-d H:i:s', time() + $duration);
        }
        
        $stmt = $mysqli->prepare("INSERT INTO ip_blocks (ip_address, reason, blocked_until, created_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE reason = VALUES(reason), blocked_until = VALUES(blocked_until)");
        if ($stmt) {
            $stmt->bind_param('sss', $ip, $reason, $blockedUntil);
            $success = $stmt->execute();
            $stmt->close();
            return $success;
        }
    } catch (Exception $e) {
        error_log("IP block error: " . $e->getMessage());
    }
    
    return false;
}