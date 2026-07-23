<?php
require_once __DIR__ . '/../security/SecurityUtils.php';

class PortScannerModel {
    private $mysqli;
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    
    private function scanPort($host, $port) {
        $start_time = microtime(true);
        
        $connection = @fsockopen($host, $port, $errno, $errstr, 0.1);
        $end_time = microtime(true);
        $response_time = ($end_time - $start_time) * 1000;
        
        if (is_resource($connection)) {
            fclose($connection);
            return ['status' => 'open', 'response_time' => round($response_time, 2)];
        }
        
        switch ($errno) {
            case 110:
            case 10060:
                return ['status' => 'filtered', 'response_time' => round($response_time, 2)];
            case 0:
            case 111:
            case 113:
            case 101:
            case 102:
            case 103:
            case 104:
            default:
                return ['status' => 'closed', 'response_time' => round($response_time, 2)];
        }
    }
    
    private function getServiceName($port) {
        $services = [
            20 => 'FTP-data', 21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
            67 => 'DHCP', 68 => 'DHCP', 69 => 'TFTP', 80 => 'HTTP', 110 => 'POP3', 123 => 'NTP',
            137 => 'NetBIOS', 138 => 'NetBIOS', 139 => 'NetBIOS', 143 => 'IMAP', 161 => 'SNMP',
            162 => 'SNMP-trap', 389 => 'LDAP', 443 => 'HTTPS', 445 => 'SMB', 636 => 'LDAPS',
            993 => 'IMAPS', 995 => 'POP3S', 1433 => 'MSSQL', 1521 => 'Oracle', 3306 => 'MySQL',
            3389 => 'RDP', 5432 => 'PostgreSQL', 5900 => 'VNC', 5901 => 'VNC-1', 5902 => 'VNC-2',
            5903 => 'VNC-3', 6379 => 'Redis', 8080 => 'HTTP-alt', 8443 => 'HTTPS-alt',
            9000 => 'Webmin', 9090 => 'Webmin-alt', 27017 => 'MongoDB', 27018 => 'MongoDB-shard',
            27019 => 'MongoDB-config', 50070 => 'Hadoop-NameNode', 50075 => 'Hadoop-DataNode',
            50090 => 'Hadoop-SecondaryNameNode'
        ];
        return isset($services[$port]) ? $services[$port] : 'unknown';
    }
    
    public function scanHost($host) {
        if (empty($host)) {
            return ['error' => 'Host parameter is required.'];
        }
        
        if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && !filter_var($host, FILTER_VALIDATE_IP)) {
            return ['error' => 'Invalid host format. Please provide a valid IP address or domain name.'];
        }
        
        set_time_limit(20);
        
        $ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 5902, 5903, 6379, 8080, 8443, 9000, 9090, 27017, 27018, 27019, 50070, 50075, 50090];
        
        $results = [];
        $open_ports = [];
        $closed_ports = [];
        $filtered_ports = [];
        
        foreach ($ports as $port) {
            $scan_result = $this->scanPort($host, $port);
            $service = $this->getServiceName($port);
            
            $port_result = [
                'port' => $port,
                'status' => $scan_result['status'],
                'service' => $service,
                'response_time' => $scan_result['response_time']
            ];
            
            $results[] = $port_result;
            
            if ($scan_result['status'] === 'open') {
                $open_ports[] = $port;
            } elseif ($scan_result['status'] === 'filtered') {
                $filtered_ports[] = $port;
            } else {
                $closed_ports[] = $port;
            }
        }
        
        return [
            'host' => $host,
            'open_ports' => $open_ports,
            'closed_ports' => $closed_ports,
            'filtered_ports' => $filtered_ports,
            'scanned_ports_count' => count($ports),
            'results' => $results
        ];
    }
}
?> 