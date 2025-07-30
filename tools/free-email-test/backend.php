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
        die("Database connection failed. Please try again later.");
    }
    $mysqli->set_charset("utf8mb4");
    $mysqli->query("SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'");
} catch (Exception $e) {
    error_log("Database connection exception: " . $e->getMessage());
    die("Database connection failed. Please try again later.");
}

function log_lookup($mysqli, $tool, $input, $errorMessage = null) {
    if ($mysqli->connect_errno) return;
    try {
        $tool = is_string($tool) ? substr(trim($tool), 0, 100) : '';
        $input = is_string($input) ? substr(trim($input), 0, 1000) : '';
        $errorMessage = is_string($errorMessage) ? substr(trim($errorMessage), 0, 500) : null;

        $stmt = $mysqli->prepare("INSERT INTO lookup_logs (tool, input, error_message) VALUES (?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param('sss', $tool, $input, $errorMessage);
            $stmt->execute();
            $stmt->close();
        }
    } catch (Exception $e) {
        error_log("Log error: " . $e->getMessage());
    }
}

function check_email_domain($email) {
    global $mysqli;

    $result = "";
    $email = strtolower(trim($email));
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $result = "❌ Invalid email format.";
        log_lookup($mysqli, 'free-email-test', $email, $result);
    } else {
        $domain = substr(strrchr($email, "@"), 1);

        try {
            $stmt = $mysqli->prepare("SELECT 1 FROM free_email_domains WHERE domain = ?");
            if ($stmt) {
                $stmt->bind_param("s", $domain);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $result = "✅ This is a free email provider: $domain";
                } else {
                    $result = "ℹ️ This looks like a custom or corporate email domain: $domain";
                }

                $stmt->close();
                log_lookup($mysqli, 'free-email-test', $email);
            } else {
                $result = "⚠️ Database query error.";
                log_lookup($mysqli, 'free-email-test', $email, "Query error");
            }
        } catch (Exception $e) {
            $result = "❌ Internal error.";
            log_lookup($mysqli, 'free-email-test', $email, "Exception: " . $e->getMessage());
        }
    }

    $mysqli->close(); 
    return $result;
}

