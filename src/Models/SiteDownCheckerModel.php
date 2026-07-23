<?php
class SiteDownCheckerModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function check($url) {
        if (!preg_match('/^https?:\/\//i', $url)) $url = 'https://' . $url;
        require_once __DIR__ . '/../Security/SecurityUtils.php';
        if (!SecurityUtils::validateURL($url)) return ['error' => 'Invalid URL format provided.'];
        $parsed_url = parse_url($url);
        if (!$parsed_url || !isset($parsed_url['host'])) return ['error' => 'Unable to parse URL.'];
        $hostname = $parsed_url['host'];
        $port = $parsed_url['port'] ?? ($parsed_url['scheme'] === 'https' ? 443 : 80);
        $dns = $this->resolve_dns($hostname);
        if ($dns['status'] !== 'ok') {
            return [
                'overall_status' => 'fail',
                'summary' => "The site $hostname appears to be down (DNS resolution failed).",
                'results' => [['test' => 'DNS resolution', 'details' => 'Failed', 'status' => 'fail']],
                'troubleshooting_steps' => $this->getSteps()
            ];
        }
        $ip = $dns['ips'][0];
        
        // Store Intelligence
        if (filter_var($ip, FILTER_VALIDATE_IP) && $hostname !== $ip) {
            require_once __DIR__ . '/../Includes/DatabaseManager.php';
            DatabaseManager::storeIpDomainMapping($this->mysqli, $hostname, $ip, 'site_down_checker', 80);
            DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
        }
        
        $ping = $this->ping_host($ip);
        $p80 = $this->check_port($ip, 80);
        $p443 = $this->check_port($ip, 443);
        $http = $this->fetch_http($url);
        $results = [
            ['test' => 'DNS resolution', 'details' => 'Resolves to ' . implode(', ', $dns['ips']), 'status' => 'ok'],
            ['test' => 'Ping response', 'details' => $ping['details'], 'status' => $ping['status']],
            ['test' => 'Web ports (80/443)', 'details' => "80:{$p80['status']}, 443:{$p443['status']}", 'status' => ($p80['status'] === 'open' || $p443['status'] === 'open') ? 'ok' : 'fail'],
            ['test' => 'HTTP status', 'details' => $http['details'], 'status' => $http['status']]
        ];
        return [
            'overall_status' => $http['status'],
            'summary' => $http['status'] === 'ok' ? "The site $hostname is up." : "The site $hostname has issues.",
            'results' => $results,
            'troubleshooting_steps' => $this->getSteps()
        ];
    }
    private function resolve_dns($host) {
        $ips = gethostbynamel($host);
        return $ips ? ['status' => 'ok', 'ips' => $ips] : ['status' => 'fail'];
    }
    private function ping_host($ip) {
        $status = 'fail'; $detail = 'Ping failed';
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') $cmd = "ping -n 1 -w 500 " . escapeshellarg($ip);
        else $cmd = "ping -c 1 -W 1 " . escapeshellarg($ip);
        exec($cmd, $out, $ret);
        if ($ret === 0) { $status = 'ok'; $detail = 'Ping successful'; }
        return ['status' => $status, 'details' => $detail];
    }
    private function check_port($ip, $port) {
        $fp = @fsockopen($ip, $port, $err, $errs, 1);
        if ($fp) { fclose($fp); return ['status' => 'open']; }
        return ['status' => 'closed'];
    }
    private function fetch_http($url) {
        $ch = curl_init($url);
        curl_setopt_all($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_USERAGENT => 'SiteChecker/1.0']);
        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 400) return ['status' => 'ok', 'details' => "HTTP $code - OK"];
        return ['status' => 'fail', 'details' => "HTTP $code - Error"];
    }
    private function getSteps() {
        return ['Check your internet connection.', 'Clear browser cache.', 'Flush local DNS.', 'Try different browser.'];
    }
}
function curl_setopt_all($ch, $opts) { foreach($opts as $k => $v) curl_setopt($ch, $k, $v); }