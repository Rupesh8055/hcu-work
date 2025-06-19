<?php
// backend.php - Pure Backend API for Chinese Firewall Test

// Include Composer's autoload file for Net_DNS2_Resolver
$autoload_path = __DIR__ . '/vendor/autoload.php';
if (!file_exists($autoload_path)) {
    // In a production environment, you might log this error and display a user-friendly message.
    // For an API, it's crucial to return a machine-readable error.
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Server Error: Composer autoload file not found. Please run "composer require pear/net_dns2".']);
    exit;
}
require_once $autoload_path;

use Net_DNS2_Resolver as Resolver;

// Verify Net_DNS2\Resolver class exists
if (!class_exists('Net_DNS2_Resolver')) {
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Server Error: Net_DNS2_Resolver class not found. Ensure "pear/net_dns2" is properly installed.']);
    exit;
} 

// List of trusted DNS servers for fallback
$TRUSTED_DNS_SERVERS = [
    ['name' => 'Google', 'ip' => '8.8.8.8'],
    ['name' => 'Cloudflare', 'ip' => '1.1.1.1'],
    ['name' => 'Quad9', 'ip' => '9.9.9.9']
];

/**
 * Resolves the A record for a given domain using a specific DNS server.
 *
 * @param string $domain The domain to resolve.
 * @param string $dns_server The IP address of the DNS server to use.
 * @return string The resolved IP address or an error message.
 */
function resolve_with_dns($domain, $dns_server) {
    try {
        $resolver = new Resolver(['nameservers' => [$dns_server], 'timeout' => 5]);
        $response = $resolver->query($domain, 'A');
        
        foreach ($response->answer as $record) {
            if ($record->type === 'A') {
                return $record->address;
            }
        }
        
        return "Error: No valid IP found for {$dns_server}";
    } catch (Exception $e) {
        if (strpos($e->getMessage(), 'timeout') !== false) {
            return "Error: Timeout connecting to {$dns_server}";
        }
        return "Error: DNS resolution failed for {$dns_server}: {$e->getMessage()}";
    }
}

/**
 * Checks for DNS poisoning across multiple DNS servers.
 *
 * @param string $domain The domain to check.
 * @return array An associative array containing DNS resolution results and poisoning detection status.
 */
function check_dns_poisoning($domain) {
    $results = [
        'local_ip' => null,
        'trusted_dns_results' => [],
        'dns_poisoning_detected' => false,
        'dns_servers_failed' => []
    ];
    
    // Get local DNS resolution
    $local_ip = gethostbyname($domain);
    $results['local_ip'] = ($local_ip !== $domain) ? $local_ip : 'Local DNS resolution failed';
    
    // Resolve with trusted DNS servers
    global $TRUSTED_DNS_SERVERS;
    foreach ($TRUSTED_DNS_SERVERS as $server) {
        $trusted_ip = resolve_with_dns($domain, $server['ip']);
        $results['trusted_dns_results'][] = [
            'dns_server' => "{$server['name']} ({$server['ip']})",
            'ip' => $trusted_ip
        ];
        if (strpos($trusted_ip, 'Error') === 0) {
            $results['dns_servers_failed'][] = $server['ip'];
        }
    }
    
    // Check for poisoning
    if ($results['local_ip'] !== 'Local DNS resolution failed') {
        foreach ($results['trusted_dns_results'] as $trusted_result) {
            $trusted_ip = $trusted_result['ip'];
            if (strpos($trusted_ip, 'Error') !== false || strpos($trusted_ip, 'No valid IP') !== false) {
                // Skip if trusted_ip is an error message
                continue;
            }
            if ($results['local_ip'] !== $trusted_ip) {
                $results['dns_poisoning_detected'] = true;
                break;
            }
        }
    }
    
    return $results;
}

/**
 * Tests TCP connectivity to a domain on a specific port and checks for GFW TCP RST.
 *
 * @param string $domain The domain to connect to.
 * @param int $port The port number (default is 80 for HTTP).
 * @return array An associative array indicating accessibility and GFW RST detection.
 */
function check_tcp_connectivity($domain, $port = 80) {
    $ip = gethostbyname($domain);
    if ($ip === $domain) {
        return [
            'accessible' => false,
            'gfw_rst_detected' => false,
            'error' => 'DNS resolution failed'
        ];
    }
    
    // Attempt TCP connection
    $timeout = 5;
    $fp = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    
    if ($fp) {
        fclose($fp);
        return [
            'accessible' => true,
            'gfw_rst_detected' => false
        ];
    }
    
    // Approximate GFW RST detection based on error
    $is_rst = strpos($errstr, 'reset') !== false || $errno === 111; // Connection refused may indicate RST
    return [
        'accessible' => false,
        'gfw_rst_detected' => $is_rst,
        'error' => $errstr ?: 'Connection failed'
    ];
}

/**
 * Performs an HTTP GET request to a URL with retries and checks for GFW blocking.
 *
 * @param string $url The URL to request.
 * @param int $retries The number of times to retry the request.
 * @return array An associative array indicating HTTP accessibility and GFW block suspicion.
 */
function check_http_request($url, $retries = 2) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    for ($attempt = 0; $attempt < $retries; $attempt++) {
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        
        if ($response !== false && $http_code >= 200 && $http_code < 400) {
            curl_close($ch);
            return [
                'http_accessible' => true,
                'status_code' => $http_code,
                'gfw_block_suspected' => false
            ];
        }
        
        if ($attempt === $retries - 1) {
            curl_close($ch);
            if (strpos($error, 'reset') !== false || strpos($error, 'timeout') !== false) {
                return [
                    'http_accessible' => false,
                    'status_code' => null,
                    'gfw_block_suspected' => true // Possible GFW block or timeout
                ];
            }
            return [
                'http_accessible' => false,
                'status_code' => null,
                'gfw_block_suspected' => false
            ];
        }
    }
    
    curl_close($ch);
    return [
        'http_accessible' => false,
        'status_code' => null,
        'gfw_block_suspected' => false
    ];
}

/**
 * Main analysis function
 *
 * @param string $input_url The URL to analyze.
 * @return array A comprehensive report of the analysis.
 */
function analyze_url($input_url) {
    $parsed = parse_url($input_url);
    $domain = isset($parsed['host']) ? $parsed['host'] : $parsed['path'];
    $full_url = isset($parsed['scheme']) ? $input_url : "http://{$input_url}";
    
    $result = [
        'url' => $full_url,
        'domain' => $domain,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    // DNS Check
    $dns_result = check_dns_poisoning($domain);
    $result = array_merge($result, $dns_result);
    
    // TCP Connectivity
    $tcp_result = check_tcp_connectivity($domain);
    $result['tcp_connectivity'] = $tcp_result;
    
    // HTTP Request
    $http_result = check_http_request($full_url);
    $result = array_merge($result, $http_result);
    
    // Determine overall GFW status
    if ($dns_result['dns_poisoning_detected']) {
        $result['gfw_status'] = 'DNS Poisoning Suspected';
    } elseif (!empty($dns_result['dns_servers_failed'])) {
        $result['gfw_status'] = 'DNS Server(s) Failed: ' . implode(', ', $dns_result['dns_servers_failed']) . '. Check if DNS servers are blocked.';
    } elseif ($tcp_result['gfw_rst_detected']) {
        $result['gfw_status'] = 'TCP RST Detected - Possible GFW Block';
    } elseif (!$tcp_result['accessible']) {
        $result['gfw_status'] = 'TCP Connection Failed - Possible IP Block';
    } elseif ($http_result['gfw_block_suspected']) {
        $result['gfw_status'] = 'HTTP Block Suspected - Possible GFW Filtering';
    } elseif (!$http_result['http_accessible']) {
        $result['gfw_status'] = 'HTTP Request Failed - Possible Network Issue';
    } else {
        $result['gfw_status'] = 'No GFW Issues Detected';
    }
    
    return $result;
}

// Main entry point for the API
header('Content-Type: application/json'); // Always return JSON

if (isset($_GET['domain']) && trim($_GET['domain']) !== '') {
    $url_input = filter_input(INPUT_GET, 'domain', FILTER_SANITIZE_URL);
    if ($url_input) {
        $results = analyze_url($url_input);
        echo json_encode($results, JSON_PRETTY_PRINT);
    } else {
        echo json_encode(['error' => 'Invalid domain provided.']);
    }
} else {
    echo json_encode(['message' => 'This is the API endpoint for the Chinese Firewall Test. Please provide a "domain" parameter in the GET request.']);
}
exit; // Terminate script execution after sending JSON response
?>
