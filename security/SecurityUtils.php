<?php
class SecurityUtils {

    private static $rateLimitWindow = 3600;
    private static $maxRequestsPerHour = 100;

    public static function sanitizeInput($input, $type = 'general', $maxLength = 255) {
        if (empty($input) || !is_string($input)) {
            return false;
        }

        $input = trim($input);

        if (strlen($input) > $maxLength) {
            return false;
        }

        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);

        switch ($type) {
            case 'ip':
                return self::validateIP($input) ? $input : false;

            case 'domain':
                return self::validateDomain($input) ? $input : false;

            case 'url':
                return self::validateURL($input) ? $input : false;

            case 'email':
                return self::validateEmail($input) ? $input : false;

            case 'mac':
                return self::validateMAC($input) ? $input : false;

            case 'port':
                return self::validatePort($input) ? $input : false;

            case 'dns_type':
                return self::validateDNSType($input) ? $input : false;

            case 'general':
            default:
                $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $input = preg_replace('/[<>]/', '', $input);
                return $input;
        }
    }

    public static function sanitizeOutput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeOutput'], $data);
        }
        
        if (is_string($data)) {
            return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        return $data;
    }

    public static function sanitizeSQL($input) {
        if (empty($input) || !is_string($input)) {
            return '';
        }
        
        $input = trim($input);
        $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
        $input = preg_replace('/[<>]/', '', $input);
        
        return $input;
    }

    public static function validateIP($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    public static function validateDomain($domain) {
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $domain)) {
            return false;
        }

        if (strlen($domain) > 253) {
            return false;
        }

        $parts = explode('.', $domain);
        if (count($parts) < 2) {
            return false;
        }

        return true;
    }

    public static function validateURL($url) {
        $sanitized = filter_var($url, FILTER_SANITIZE_URL);
        if ($sanitized === false) {
            return false;
        }

        return filter_var($sanitized, FILTER_VALIDATE_URL) !== false;
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function validateMAC($mac) {
        return preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac);
    }

    public static function validatePort($port) {
        return is_numeric($port) && $port >= 1 && $port <= 65535;
    }

    public static function validateDNSType($type) {
        $validTypes = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'PTR', 'SOA', 'SRV', 'CAA'];
        return in_array(strtoupper($type), $validTypes);
    }

    public static function checkRateLimit($mysqli, $ip, $tool) {
        if (!$mysqli || $mysqli->connect_errno) {
            return true;
        }

        try {
            $ip = self::sanitizeSQL($ip);
            $tool = self::sanitizeSQL($tool);
            
            $windowStart = date('Y-m-d H:i:s', time() - self::$rateLimitWindow);
            
            $stmt = $mysqli->prepare("SELECT COUNT(*) as count FROM lookup_logs WHERE ip_address = ? AND tool = ? AND created_at > ?");
            if ($stmt) {
                $stmt->bind_param('sss', $ip, $tool, $windowStart);
                $stmt->execute();
                $result = $stmt->get_result();
                $row = $result->fetch_assoc();
                $stmt->close();
                
                return $row['count'] < self::$maxRequestsPerHour;
            }
        } catch (Exception $e) {
            error_log("Rate limit check error: " . $e->getMessage());
        }
        
        return true;
    }

    public static function getClientIP() {
        $ipKeys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];

        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    public static function detectSuspiciousPatterns($input) {
        $patterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onerror\s*=/i',
            '/onclick\s*=/i',
            '/union\s+select/i',
            '/drop\s+table/i',
            '/insert\s+into/i',
            '/delete\s+from/i',
            '/update\s+set/i',
            '/exec\s*\(/i',
            '/eval\s*\(/i',
            '/system\s*\(/i'
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    public static function setSecurityHeaders() {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\' https:; connect-src \'self\'; frame-ancestors \'none\';');
    }
}
?>