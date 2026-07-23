<?php
class SecurityMiddleware {

    private $mysqli;
    private $toolName;

    public function __construct($mysqli, $toolName) {
        $this->mysqli = $mysqli;
        $this->toolName = $toolName;
    }

    public function applySecurity() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        SecurityUtils::setSecurityHeaders();

        $clientIP = SecurityUtils::getClientIP();

        if (is_ip_blocked($this->mysqli, $clientIP)) {
            $this->blockedResponse();
        }

        if (!SecurityUtils::checkRateLimit($this->mysqli, $clientIP, $this->toolName)) {
            $this->rateLimitResponse();
        }

        return $clientIP;
    }

    public function sanitizeInput($input, $type = 'general', $maxLength = 255) {
        $sanitized = SecurityUtils::sanitizeInput($input, $type, $maxLength);

        if ($sanitized === false) {
            SecurityUtils::logSecurityEvent($this->mysqli, 'INVALID_INPUT', "Invalid input in {$this->toolName}: " . substr($input, 0, 100), 'WARNING');
            $this->invalidInputResponse();
        }

        if (SecurityUtils::detectSuspiciousPatterns($input)) {
            SecurityUtils::logSecurityEvent($this->mysqli, 'SUSPICIOUS_INPUT', "Suspicious input detected in {$this->toolName}: " . substr($input, 0, 100), 'WARNING');
            $this->suspiciousInputResponse();
        }

        return $sanitized;
    }

    public function validateInput($input, $validationType) {
        switch ($validationType) {
            case 'ip':
                if (!SecurityUtils::validateIP($input)) {
                    $this->invalidInputResponse('Invalid IP address format.');
                }
                break;

            case 'domain':
                if (!SecurityUtils::validateDomain($input)) {
                    $this->invalidInputResponse('Invalid domain name format.');
                }
                break;

            case 'url':
                if (!SecurityUtils::validateURL($input)) {
                    $this->invalidInputResponse('Invalid URL format.');
                }
                break;

            case 'email':
                if (!SecurityUtils::validateEmail($input)) {
                    $this->invalidInputResponse('Invalid email address format.');
                }
                break;

            case 'mac':
                if (!SecurityUtils::validateMAC($input)) {
                    $this->invalidInputResponse('Invalid MAC address format.');
                }
                break;

            case 'port':
                if (!SecurityUtils::validatePort($input)) {
                    $this->invalidInputResponse('Invalid port number.');
                }
                break;

            case 'dns_type':
                if (!SecurityUtils::validateDNSType($input)) {
                    $this->invalidInputResponse('Invalid DNS record type.');
                }
                break;
        }

        return $input;
    }

    public function logSecurityEvent($event, $details, $severity = 'INFO') {
        SecurityUtils::logSecurityEvent($this->mysqli, $event, $details, $severity);
    }

    public function blockIP($ip, $reason = '', $duration = null) {
        return block_ip($this->mysqli, $ip, $reason, $duration);
    }

    public function sanitizeOutput($data) {
        return SecurityUtils::sanitizeOutput($data);
    }

    private function blockedResponse() {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Access denied. Your IP address has been blocked.']);
        exit;
    }

    private function rateLimitResponse() {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Rate limit exceeded. Please try again later.']);
        exit;
    }

    private function invalidInputResponse($message = 'Invalid input provided.') {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => $message]);
        exit;
    }

    private function suspiciousInputResponse() {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Suspicious input detected.']);
        exit;
    }

    public function handleException($exception) {
        error_log("Error in {$this->toolName}: " . $exception->getMessage());

        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'An internal error occurred. Please try again later.']);
        exit;
    }

    public function validateMethod($allowedMethods = ['GET']) {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if (!in_array($method, $allowedMethods)) {
            http_response_code(405);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Method not allowed.']);
            exit;
        }

        return $method;
    }

    public function validateRequiredParams($params) {
        $missing = [];

        foreach ($params as $param) {
            if (!isset($_GET[$param]) || empty($_GET[$param])) {
                $missing[] = $param;
            }
        }

        if (!empty($missing)) {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Missing required parameters: ' . implode(', ', $missing)]);
            exit;
        }

        return true;
    }

    public function getParam($param, $type = 'general', $maxLength = 255, $default = '') {
        $value = $_GET[$param] ?? $default;
        return $this->sanitizeInput($value, $type, $maxLength);
    }

    public function applyCORS($allowedOrigins = []) {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        if (empty($allowedOrigins) || in_array($origin, $allowedOrigins)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type');
        }

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
    }
}
?>