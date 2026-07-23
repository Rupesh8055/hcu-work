<?php
class ReverseDnsModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function reverseLookup($ip) {
        if (empty($ip)) {
            return ['error' => 'IP address cannot be empty.'];
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['error' => 'Invalid IP address provided.'];
        }
        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            return [
                'ip' => $ip,
                'hostname' => 'No reverse DNS record found',
                'status' => 'not_found'
            ];
        }
        return [
            'ip' => $ip,
            'hostname' => $hostname,
            'status' => 'found'
        ];
    }
}
