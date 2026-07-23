<?php
class PortScannerModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function scan($host, $customPorts = null) {
        if (empty($host)) return ['error' => 'Host parameter is required.'];
        
        // Resolve domain to IP for more reliable scanning
        $ip = gethostbyname($host);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
             return ['error' => 'Invalid hostname or IP address.'];
        }
        
        // Populate Intelligence Database
        require_once __DIR__ . '/../Includes/DatabaseManager.php';
        if ($host !== $ip) {
            DatabaseManager::storeIpDomainMapping($this->mysqli, $host, $ip, 'port_scanner', 80);
            DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
        }

        $ports = [];
        if (!empty($customPorts)) {
            $parts = explode(',', $customPorts);
            foreach ($parts as $part) {
                $part = trim($part);
                if (is_numeric($part) && $part > 0 && $part <= 65535) {
                    $ports[] = (int)$part;
                }
            }
            $ports = array_unique($ports);
            // Limit to 50 ports max to prevent abuse
            $ports = array_slice($ports, 0, 50);
        }
        
        if (empty($ports)) {
            // Default top 50 ports
            $ports = [
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162,
                389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 3306, 3389,
                5060, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 10000, 11211, 27017
            ];
        }
        $sockets = [];
        $results = [];
        $open_ports = [];
        $closed_ports = [];
        $filtered_ports = [];

        // Initiate all connections asynchronously using curl_multi
        $mh = curl_multi_init();
        $handles = [];
        $timeout_ms = 1000;

        foreach ($ports as $port) {
            $ch = curl_init("telnet://$ip:$port");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $timeout_ms);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeout_ms);
            curl_multi_add_handle($mh, $ch);
            $handles[$port] = $ch;
        }

        $active = null;
        do {
            $mrc = curl_multi_exec($mh, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);

        while ($active && $mrc == CURLM_OK) {
            if (curl_multi_select($mh) == -1) {
                usleep(100);
            }
            do {
                $mrc = curl_multi_exec($mh, $active);
            } while ($mrc == CURLM_CALL_MULTI_PERFORM);
        }

        // Process results
        while ($info = curl_multi_info_read($mh)) {
            $ch = $info['handle'];
            $port = array_search($ch, $handles);
            if ($port !== false) {
                $curl_result = $info['result']; // 7 = COULDNT_CONNECT (Closed), 28 = TIMEDOUT (Filtered)
                $cinfo = curl_getinfo($ch);
                $connect_time = $cinfo['connect_time'];
                
                if ($connect_time > 0) {
                    $open_ports[] = $port;
                    $results[$port] = [
                        'port' => $port,
                        'status' => 'open',
                        'service' => $this->getServiceName($port),
                        'state_explanation' => $this->getStateExplanation('open'),
                        'response_time' => round($connect_time * 1000, 2)
                    ];
                } elseif ($curl_result == 7) { // CURLE_COULDNT_CONNECT
                    $closed_ports[] = $port;
                    $results[$port] = [
                        'port' => $port,
                        'status' => 'closed',
                        'service' => $this->getServiceName($port),
                        'state_explanation' => $this->getStateExplanation('closed'),
                        'response_time' => 0
                    ];
                } else {
                    $filtered_ports[] = $port;
                    $results[$port] = [
                        'port' => $port,
                        'status' => 'filtered',
                        'service' => $this->getServiceName($port),
                        'state_explanation' => $this->getStateExplanation('filtered'),
                        'response_time' => $timeout_ms
                    ];
                }
            }
        }

        foreach ($handles as $port => $ch) {
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        ksort($results);
        $results = array_values($results);

        return [
            'host' => $host,
            'ip' => $ip,
            'results' => $results,
            'open_ports' => $open_ports,
            'closed_ports' => $closed_ports,
            'filtered_ports' => $filtered_ports,
            'scanned_ports_count' => count($ports),
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => 'internal_socket_scan'
        ];
    }
    private function getServiceName($port) {
        $svcs = [
            20 => 'FTP Data', 21 => 'FTP Control', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS', 
            67 => 'DHCP Server', 68 => 'DHCP Client', 69 => 'TFTP', 80 => 'HTTP', 110 => 'POP3', 
            119 => 'NNTP', 123 => 'NTP', 135 => 'RPC', 137 => 'NetBIOS Name', 138 => 'NetBIOS Datagram', 
            139 => 'NetBIOS Session', 143 => 'IMAP', 161 => 'SNMP', 162 => 'SNMP Trap', 389 => 'LDAP', 
            443 => 'HTTPS', 445 => 'SMB', 465 => 'SMTPS', 514 => 'Syslog', 587 => 'SMTP Submission', 
            636 => 'LDAPS', 993 => 'IMAPS', 995 => 'POP3S', 1080 => 'SOCKS Proxy', 1433 => 'MS SQL', 
            1521 => 'Oracle', 1723 => 'PPTP', 2049 => 'NFS', 3306 => 'MySQL', 3389 => 'RDP', 
            5060 => 'SIP', 5432 => 'PostgreSQL', 5900 => 'VNC', 6379 => 'Redis', 8000 => 'HTTP-Alt', 
            8080 => 'HTTP-Proxy', 8443 => 'HTTPS-Alt', 8888 => 'HTTP-Alt', 9000 => 'CS Listener', 
            9090 => 'WebSM', 9200 => 'Elasticsearch', 10000 => 'Webmin', 11211 => 'Memcached', 27017 => 'MongoDB'
        ];
        return $svcs[$port] ?? 'Unknown';
    }
    private function getStateExplanation($status) {
        switch ($status) {
            case 'open':
                return 'An application is actively accepting TCP connections or UDP datagrams on this port.';
            case 'closed':
                return 'A closed port is accessible but there is no application listening on it.';
            case 'filtered':
                return 'A firewall, filter, or other network obstacle is blocking the port so we cannot determine its status.';
            default:
                return 'The state of the port could not be determined.';
        }
    }
}