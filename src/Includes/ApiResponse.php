<?php

class ApiResponse {
    /**
     * Standardizes all tool responses into a strict backend schema.
     */
    public static function format($tool, $query, $result, $cached = false) {
        $success = true;
        $errors = [];
        $warnings = [];
        $data = null;

        if (is_array($result)) {
            if (isset($result['error'])) {
                $success = false;
                $errors[] = $result['error'];
            } elseif (isset($result['response']['error'])) {
                $success = false;
                $errors[] = $result['response']['error'];
            } else {
                $data = isset($result['response']) ? $result['response'] : $result;
                // Preserve explicit cached flags from controller if present
                if (isset($result['cached'])) {
                    $cached = $result['cached'];
                }
                
                if (isset($result['errors'])) {
                    $errors = array_merge($errors, (array)$result['errors']);
                }
                if (isset($result['warnings'])) {
                    $warnings = array_merge($warnings, (array)$result['warnings']);
                }
                
                // Remove redundant internal format elements from output data
                if (is_array($data)) {
                    unset($data['cached']);
                    unset($data['errors']);
                    unset($data['warnings']);
                }
            }
        } else {
            $success = false;
            $errors[] = 'Invalid or empty backend response structure received.';
        }

        // Failure-state Intelligence: explain WHY
        if (!$success) {
            if (empty($errors)) {
                $errors[] = "An unidentified server-side processing error occurred.";
            }
            // Enhance error messages with failure-state intelligence
            foreach ($errors as $idx => $err) {
                if (stripos($err, 'connection refused') !== false || stripos($err, 'timed out') !== false || stripos($err, 'blocked') !== false) {
                    $errors[$idx] = $err . " (Reason: Network port 43 WHOIS or port 53 DNS socket connection failed. This usually indicates local firewalls are blocking outgoing raw TCP/UDP socket traffic on this server.)";
                } elseif (stripos($err, 'invalid') !== false) {
                    $errors[$idx] = $err . " (Reason: The input query string does not match standard FQDN, domain hostname, or IPv4/IPv6 address syntax patterns.)";
                }
            }
        }

        return [
            'success' => $success,
            'tool' => $tool,
            'query' => $query,
            'generated_at' => date('c'),
            'cached' => (bool)$cached,
            'data' => $data,
            'errors' => $errors,
            'warnings' => $warnings
        ];
    }

    public static function success($data = [], $message = 'Success') {
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'success',
            'message' => $message,
            'timestamp' => date('c'),
            'response' => $data
        ]);
        exit;
    }

    public static function error($message, $code = 400, $details = null) {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'code' => $code,
            'message' => $message,
            'timestamp' => date('c'),
            'details' => $details
        ]);
        exit;
    }

    public static function validateMethod($method = 'GET') {
        if ($_SERVER['REQUEST_METHOD'] !== $method) {
            self::error('Method Not Allowed', 405);
        }
    }
}