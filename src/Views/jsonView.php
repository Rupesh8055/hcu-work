<?php

function renderJson($data) {
    if (ob_get_length()) ob_clean();
    
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    // Dynamic Extraction of Tool and Query for Centralized Formatting
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    $parts = explode('/', trim($path, '/'));
    $toolIndex = array_search('tools', $parts);
    $tool = '';
    $query = '';

    if ($toolIndex !== false && isset($parts[$toolIndex + 1])) {
        $tool = $parts[$toolIndex + 1];
        if (isset($parts[$toolIndex + 2])) {
            $query = rawurldecode($parts[$toolIndex + 2]);
        }
    }

    if (empty($tool)) {
        $scriptPath = $_SERVER['SCRIPT_NAME'] ?? '';
        $parts = explode('/', trim($scriptPath, '/'));
        if (count($parts) >= 2) {
            $tool = $parts[count($parts) - 2];
        }
    }

    if (empty($query)) {
        $query = $_GET['domain'] ?? $_GET['ip'] ?? $_GET['email'] ?? $_GET['mac'] ?? $_GET['q'] ?? $_GET['url'] ?? $_GET['asn'] ?? $_GET['host'] ?? $_GET['ns'] ?? '';
    }

    if (empty($tool)) $tool = 'unknown-tool';
    if (empty($query)) $query = 'none';

    // Standardize Response Format
    $formatted = [];
    if (is_array($data) && isset($data['success'], $data['tool'], $data['query'], $data['generated_at'])) {
        $formatted = $data;
    } else {
        $cached = false;
        if (is_array($data) && isset($data['cached'])) {
            $cached = $data['cached'];
        }
        if (class_exists('ApiResponse')) {
            $formatted = ApiResponse::format($tool, $query, $data, $cached);
        } else {
            // Fallback if class not loaded
            $formatted = [
                'success' => !isset($data['error']) && !isset($data['response']['error']),
                'tool' => $tool,
                'query' => $query,
                'generated_at' => date('c'),
                'cached' => $cached,
                'data' => $data['response'] ?? ($data['data'] ?? $data),
                'errors' => isset($data['error']) ? [$data['error']] : (isset($data['response']['error']) ? [$data['response']['error']] : []),
                'warnings' => []
            ];
        }
    }

    $json = json_encode($formatted, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        $error = json_last_error_msg();
        $json = json_encode([
            'success' => false,
            'tool' => $tool,
            'query' => $query,
            'generated_at' => date('c'),
            'cached' => false,
            'data' => null,
            'errors' => ['JSON Encode Error: ' . $error],
            'warnings' => []
        ]);
    }
    
    echo $json;
}

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && ($error['type'] === E_ERROR || $error['type'] === E_PARSE || $error['type'] === E_CORE_ERROR || $error['type'] === E_COMPILE_ERROR)) {
        if (ob_get_length()) ob_clean();
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
        }
        
        $tool = 'unknown-tool';
        $query = 'none';
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
        $parts = explode('/', trim($path, '/'));
        $toolIndex = array_search('tools', $parts);
        if ($toolIndex !== false && isset($parts[$toolIndex + 1])) {
            $tool = $parts[$toolIndex + 1];
            if (isset($parts[$toolIndex + 2])) {
                $query = rawurldecode($parts[$toolIndex + 2]);
            }
        }
        
        echo json_encode([
            'success' => false,
            'tool' => $tool,
            'query' => $query,
            'generated_at' => date('c'),
            'cached' => false,
            'data' => null,
            'errors' => ['Fatal Execution Error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']],
            'warnings' => []
        ]);
    }
});