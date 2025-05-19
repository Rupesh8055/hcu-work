<?php

// Require Net_DNS2 for custom DNS queries
$autoload_path = __DIR__ . '/vendor/autoload.php';
if (!file_exists($autoload_path)) {
    die('Fatal Error: Composer autoload file not found at ' . $autoload_path . '. Run "composer require pear/net_dns2" in ' . __DIR__ . '.');
}
require_once $autoload_path;

use Net_DNS2\Resolver;

// Verify Net_DNS2\Resolver class exists
if (!class_exists('Net_DNS2\Resolver')) {
    die('Fatal Error: Net_DNS2\Resolver class not found. Ensure "pear/net_dns2" is installed via Composer and vendor/autoload.php is correctly set up.');
}

// List of trusted DNS servers for fallback
$TRUSTED_DNS_SERVERS = [
    ['name' => 'Google', 'ip' => '8.8.8.8'],
    ['name' => 'Cloudflare', 'ip' => '1.1.1.1'],
    ['name' => 'Quad9', 'ip' => '9.9.9.9']
];

// Resolve domain using a specific DNS server
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

// Check for DNS poisoning across multiple DNS servers
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
            if (strpos($trusted_ip, 'Error') !== 0 && $results['local_ip'] !== $trusted_ip) {
                $results['dns_poisoning_detected'] = true;
                break;
            }
        }
    }
    
    return $results;
}

// Test TCP connectivity and check for GFW TCP RST
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

// Test HTTP GET request with retries
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

// Main analysis function
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

// Main entry point
if (php_sapi_name() === 'cli') {
    echo "Enter a URL to test for Great Firewall issues (e.g., https://www.google.com): ";
    $url_input = trim(fgets(STDIN));
    $results = analyze_url($url_input);
    echo "\n--- Great Firewall of China Test Report ---\n";
    echo json_encode($results, JSON_PRETTY_PRINT) . "\n";
} else {
    // Web interface for browser access
    $results = null;
    if (isset($_POST['url'])) {
        $url_input = filter_input(INPUT_POST, 'url', FILTER_SANITIZE_URL);
        $results = analyze_url($url_input);
        header('Content-Type: application/json');
        echo json_encode($results, JSON_PRETTY_PRINT);
        exit;
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>GFW Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            form { margin-bottom: 20px; }
            input[type="text"] { padding: 8px; width: 300px; }
            button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
            pre { background: #f8f9fa; padding: 10px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>Great Firewall of China Test</h1>
        <form method="post">
            <label>Enter URL: </label>
            <input type="text" name="url" placeholder="https://www.google.com" required>
            <button type="submit">Test</button>
        </form>
        <?php if (isset($results)): ?>
            <h2>Test Results</h2>
            <pre><?php echo json_encode($results, JSON_PRETTY_PRINT); ?></pre>
        <?php endif; ?>
    </body>
    </html>
    <?php
}
?>