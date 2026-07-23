<?php
define('SECURITY_CONFIG', [
    'RATE_LIMIT_WINDOW' => 3600,
    'MAX_REQUESTS_PER_HOUR' => 100,
    'MAX_REQUESTS_PER_MINUTE' => 10,

    'MAX_INPUT_LENGTH' => 255,
    'MAX_URL_LENGTH' => 2048,
    'MAX_DOMAIN_LENGTH' => 253,

    'SESSION_TIMEOUT' => 1800,
    'SESSION_REGENERATE_ID' => true,
    'SESSION_SECURE_COOKIES' => true,

    'MAX_FILE_SIZE' => 5242880,
    'ALLOWED_FILE_TYPES' => [
        'image/jpeg',
        'image/png',
        'image/gif',
        'text/plain',
        'application/pdf'
    ],

    'BLOCK_SUSPICIOUS_IPS' => true,
    'BLOCK_PRIVATE_IPS' => true,
    'BLOCK_RESERVED_IPS' => true,

    'LOG_SECURITY_EVENTS' => true,
    'LOG_FAILED_ATTEMPTS' => true,
    'LOG_SUSPICIOUS_ACTIVITY' => true,

    'ALLOWED_ORIGINS' => [
        'https://cyberjagrithi.com',
        'https://www.cyberjagrithi.com',
        'http://localhost'
    ],

    'SECURITY_HEADERS' => [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';",
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
    ],

    'TOOL_SECURITY' => [
        'port-scanner' => [
            'ALLOWED_PORTS' => [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 5902, 5903, 6379, 8080, 8443, 9000, 9090, 27017, 27018, 27019, 50070, 50075, 50090],
            'MAX_SCAN_TIME' => 30,
            'BLOCK_PRIVATE_IPS' => true
        ],
        'spam-database' => [
            'MAX_DNSBL_CHECKS' => 30,
            'DNS_TIMEOUT' => 5,
            'ALLOW_PRIVATE_IPS' => false
        ],
        'site-down-checker' => [
            'MAX_CHECK_TIME' => 15,
            'ALLOWED_PROTOCOLS' => ['http', 'https'],
            'BLOCK_PRIVATE_IPS' => true
        ]
    ],

    'SUSPICIOUS_PATTERNS' => [
        '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i',
        '/javascript:/i',
        '/vbscript:/i',
        '/on\w+\s*=/i',
        '/<iframe\b/i',
        '/<object\b/i',
        '/<embed\b/i',

        '/union\s+select/i',
        '/drop\s+table/i',
        '/delete\s+from/i',
        '/insert\s+into/i',
        '/update\s+set/i',
        '/alter\s+table/i',
        '/create\s+table/i',

        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/shell_exec\s*\(/i',
        '/passthru\s*\(/i',
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/file_get_contents\s*\(/i',
        '/include\s*\(/i',
        '/require\s*\(/i',

        '/\.\.\/|\.\.\\/i',
        '/~\/|~\\/i',
        '/%2e%2e%2f|%2e%2e%5c/i',
        '/%252e%252e%252f|%252e%252e%255c/i'
    ],

    'BLOCKED_IP_RANGES' => [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '0.0.0.0/8'
    ],

    'BLOCKED_USER_AGENTS' => [
        '/bot/i',
        '/crawler/i',
        '/spider/i',
        '/scraper/i',
        '/curl/i',
        '/wget/i',
        '/python/i',
        '/java/i',
        '/perl/i',
        '/ruby/i',
        '/php/i'
    ]
]);

function isIPBlocked($ip) {
    $config = SECURITY_CONFIG;
    if (!$config['BLOCK_PRIVATE_IPS'] && !$config['BLOCK_RESERVED_IPS']) {
        return false;
    }

    foreach ($config['BLOCKED_IP_RANGES'] as $range) {
        if (ipInRange($ip, $range)) {
            return true;
        }
    }

    return false;
}

function ipInRange($ip, $range) {
    list($subnet, $mask) = explode('/', $range);
    $ipLong = ip2long($ip);
    $subnetLong = ip2long($subnet);
    $maskLong = -1 << (32 - $mask);
    $subnetLong &= $maskLong;
    return ($ipLong & $maskLong) == $subnetLong;
}

function isUserAgentBlocked($userAgent) {
    $config = SECURITY_CONFIG;
    foreach ($config['BLOCKED_USER_AGENTS'] as $pattern) {
        if (preg_match($pattern, $userAgent)) {
            return true;
        }
    }
    return false;
}

function getSecurityConfig($key = null) {
    if ($key === null) {
        return SECURITY_CONFIG;
    }
    return SECURITY_CONFIG[$key] ?? null;
}

function validateToolSecurity($tool, $input) {
    $config = SECURITY_CONFIG;
    if (!isset($config['TOOL_SECURITY'][$tool])) {
        return true;
    }

    $toolConfig = $config['TOOL_SECURITY'][$tool];

    foreach ($config['SUSPICIOUS_PATTERNS'] as $pattern) {
        if (preg_match($pattern, $input)) {
            return false;
        }
    }

    return true;
}
?>