<?php
require_once __DIR__ . '/../Includes/GeoIpSystem.php';

class TracerouteModel {
    private $mysqli;
    private $geoSystem;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->geoSystem = new GeoIpSystem($mysqli);
    }

    public function trace($host) {
        $host = trim($host);
        if (empty($host)) return ['status' => 'error', 'message' => 'Host is required'];
        
        // Resolve host to IP for intelligence database
        $ip = gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP) && $host !== $ip) {
            require_once __DIR__ . '/../Includes/DatabaseManager.php';
            DatabaseManager::storeIpDomainMapping($this->mysqli, $host, $ip, 'traceroute', 70);
            DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
        }

        // Standardize host for system call
        $sanitizedHost = escapeshellarg($host);
        $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        // Use -4 to enforce IPv4 since GeoIP / ip2long conversion fails for IPv6
        // Use -d on Windows to skip DNS resolution for speed, -n on Linux
        $cmd = $isWin ? "tracert -4 -d -w 500 -h 30 $sanitizedHost" : "traceroute -4 -n -w 1 -m 30 $sanitizedHost";
        
        $out = []; $status = -1;
        exec($cmd . " 2>&1", $out, $status);

        $hops = [];
        foreach ($out as $line) {
            $line = trim($line);
            if (empty($line) || preg_match('/Tracing|over a maximum|Trace complete/i', $line)) continue;

            // Regex for hop parsing
            if (preg_match('/^\s*(\d+)\s+([\d.<ms\s*]+|[*])\s+([\d.<ms\s*]+|[*])\s+([\d.<ms\s*]+|[*])\s+([\d\w\.:-]+|[*])/', $line, $m)) {
                $ip = ($m[5] === '*' || $m[5] === 'Request') ? '' : $m[5];
                
                $hopData = [
                    'hop' => intval($m[1]),
                    'ip' => $ip,
                    'hostname' => $ip ?: 'Request Timed Out',
                    'time' => preg_match('/([\d.<]+\s*ms)/', $line, $tm) ? $tm[1] : '*',
                    'location' => 'Unknown',
                    'lat' => 0,
                    'lon' => 0,
                    'isp' => '',
                    'asn' => '',
                    'registry' => '',
                    'is_public' => false
                ];

                if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        $loc = $this->geoSystem->lookup($ip);
                        if ($loc) {
                            $hopData['location'] = ($loc['city'] !== 'Unknown' ? $loc['city'] . ', ' : '') . $loc['country'];
                            $hopData['lat'] = $loc['latitude'];
                            $hopData['lon'] = $loc['longitude'];
                            $hopData['isp'] = $loc['organization'] ?? '';
                            $hopData['asn'] = $loc['asn'] ?? '';
                            $hopData['registry'] = $loc['registry'] ?? '';
                            $hopData['is_public'] = true;
                        }
                    } else {
                        $hopData['location'] = 'Internal / Private';
                    }
                }
                $hops[] = $hopData;
            }
        }

        if (empty($hops)) return ['status' => 'error', 'message' => 'No hop data received from system traceroute.'];

        return [
            'status' => 'success',
            'host' => $host,
            'hops' => $hops,
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => 'system_traceroute'
        ];
    }
}