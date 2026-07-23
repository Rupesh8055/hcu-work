<?php
if (!function_exists('log_lookup_local')) {
    function log_lookup_local($tool, $input, $error = null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $logDir = dirname(dirname(__DIR__)) . '/logs';
        if (!is_dir($logDir)) @mkdir($logDir, 0755, true);
        $logFile = $logDir . '/lookup_fallbacks.log';
        $entry = sprintf("[%s] [%s] Tool: %s | Input: %s | Error: %s\n", date('Y-m-d H:i:s'), $ip, $tool, $input, $error ?? 'None');
        @file_put_contents($logFile, $entry, FILE_APPEND);
    }
}
if (!function_exists('log_lookup_v4')) {
    function log_lookup_v4($mysqli, $tool, $input, $error = null) {
        if (!$mysqli || !($mysqli instanceof mysqli)) {
            log_lookup_local($tool, $input, $error);
            return false;
        }
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $tool = mysqli_real_escape_string($mysqli, substr(trim($tool), 0, 64));
            $input = mysqli_real_escape_string($mysqli, substr(trim($input), 0, 1000));
            $errorEscaped = $error ? "'" . mysqli_real_escape_string($mysqli, substr(trim($error), 0, 500)) . "'" : "NULL";
            $sql = "INSERT INTO lookup_logs (user_ip, tool_name, input_query, error_message) 
                    VALUES ('$ip', '$tool', '$input', $errorEscaped)";
            if (!@mysqli_query($mysqli, $sql)) {
                log_lookup_local($tool, $input, $error);
                return false;
            }
            return true;
        } catch (Throwable $e) {
            log_lookup_local($tool, $input, $error . " | EX: " . $e->getMessage());
            return false;
        }
    }
}
if (!function_exists('log_lookup')) {
    function log_lookup($mysqli, $tool, $input, $error = null) {
        return log_lookup_v4($mysqli, $tool, $input, $error);
    }
}