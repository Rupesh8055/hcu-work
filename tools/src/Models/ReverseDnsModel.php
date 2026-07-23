<?php
class ReverseDnsModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup(string $ip): array {
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) return ['ip' => $ip, 'status' => 'error', 'message' => 'Invalid IP'];
        try {
            $h = gethostbyaddr($ip);
            if ($h === $ip) {
                $ptr = @dns_get_record(implode('.', array_reverse(explode('.', $ip))) . ".in-addr.arpa", DNS_PTR);
                if ($ptr && isset($ptr[0]['target'])) $h = $ptr[0]['target'];
                else $h = null;
            }
            return [
                'ip' => $ip,
                'hostname' => $h ?: $ip,
                'status' => $h ? 'success' : 'failed',
                'timestamp' => date('Y-m-d H:i:s')
            ];
        } catch (Exception $e) {
            return ['ip' => $ip, 'status' => 'error'];
        }
    }
}