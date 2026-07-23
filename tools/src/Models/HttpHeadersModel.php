<?php
class HttpHeadersModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getHeaders($url) {
        if (empty($url)) return ['error' => 'URL is required'];
        $u = $url;
        if (!preg_match('#^https?://#i', $u)) {
            $u = 'http://' . $u;
        }
        $headersData = $this->fetchHeaders($u);
        if ($headersData === false) return ['error' => 'Failed to connect to the server or fetch headers.'];
        return [
            'summary' => $headersData['summary'],
            'headers' => $headersData['parsed_headers'],
            'raw' => $headersData['raw_headers'],
            'chain' => $headersData['chain'] ?? []
        ];
    }
    private function fetchHeaders($url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberJagrithi/1.0');
        $res = curl_exec($ch);
        $info = curl_getinfo($ch);
        $primaryIp = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        curl_close($ch);
        
        if ($primaryIp && filter_var($primaryIp, FILTER_VALIDATE_IP)) {
            $parsedUrl = parse_url($url);
            if (isset($parsedUrl['host'])) {
                $host = $parsedUrl['host'];
                if ($host !== $primaryIp) {
                    require_once __DIR__ . '/../Includes/DatabaseManager.php';
                    DatabaseManager::storeIpDomainMapping($this->mysqli, $host, $primaryIp, 'http_headers', 85);
                    DatabaseManager::accumulateIpIntelligence($this->mysqli, $primaryIp);
                }
            }
        }
        
        if (!$res) return false;
        $blocks = preg_split('/\r\n\r\n/', trim($res));
        $final = end($blocks);
        $lines = explode("\r\n", $final);
        $parsed = [];
        array_shift($lines);
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                list($k, $v) = explode(':', $line, 2);
                $parsed[trim($k)] = trim($v);
            }
        }
        return [
            'summary' => [
                'URL' => $info['url'] ?? $url,
                'Status Code' => (string)($info['http_code'] ?? 'Unknown'),
                'Content Type' => $info['content_type'] ?? 'Unknown',
                'Redirects' => (string)($info['redirect_count'] ?? 0),
                'Connect Time' => number_format($info['connect_time'] ?? 0, 3) . 's'
            ],
            'parsed_headers' => $parsed,
            'raw_headers' => trim($res),
            'chain' => $blocks
        ];
    }
}