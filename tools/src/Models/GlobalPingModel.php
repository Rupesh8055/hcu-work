<?php
class GlobalPingModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function ping($host) {
        if (empty($host)) return ['error' => 'Host parameter is required.'];

        $results = [];

        // 1. Local Ping
        $local = $this->execPing($host);
        if (!$local['success']) {
            $tcp = $this->tcpPing($host);
            if ($tcp['success']) {
                $local = ['success' => true, 'avg' => $tcp['ms'], 'min' => $tcp['ms'], 'max' => $tcp['ms'], 'loss' => 0];
            }
        }
        $ip = gethostbyname($host);
        
        if (filter_var($ip, FILTER_VALIDATE_IP) && $host !== $ip) {
            require_once __DIR__ . '/../Includes/DatabaseManager.php';
            DatabaseManager::storeIpDomainMapping($this->mysqli, $host, $ip, 'global_ping', 80);
            DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
        }
        
        $results[] = [
            'location' => 'Primary Server',
            'region' => 'Local',
            'ip_address' => $ip,
            'status' => $local['success'] ? 'alive' : 'dead',
            'packet_loss' => $local['loss'] . '%',
            'min_time' => $local['min'] ?? $local['avg'],
            'max_time' => $local['max'] ?? $local['avg'],
            'avg_time' => $local['avg'],
            'lat' => null,
            'lon' => null
        ];

        // 2. Global Ping via free keyless API (globalping.io)
        $globalResults = $this->fetchGlobalPing($host);
        if (!empty($globalResults)) {
            foreach ($globalResults as $res) {
                $results[] = $res;
            }
        }

        return [
            'host' => $host,
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => empty($globalResults) ? 'system_native_ping' : 'globalping_api_and_local'
        ];
    }

    private function fetchGlobalPing($host) {
        $ch = curl_init('https://api.globalping.io/v1/measurements');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
            'type' => 'ping',
            'target' => $host,
            'locations' => [
                ['magic' => 'Hong Kong', 'limit' => 1],
                ['magic' => 'Mumbai', 'limit' => 1],
                ['magic' => 'Seoul', 'limit' => 1],
                ['magic' => 'Singapore', 'limit' => 1],
                ['magic' => 'Tokyo', 'limit' => 1],
                ['magic' => 'Sydney', 'limit' => 1],
                ['magic' => 'Johannesburg', 'limit' => 1],
                ['magic' => 'London', 'limit' => 1],
                ['magic' => 'Oslo', 'limit' => 1],
                ['magic' => 'Paris', 'limit' => 1],
                ['magic' => 'Amsterdam', 'limit' => 1],
                ['magic' => 'Frankfurt', 'limit' => 1],
                ['magic' => 'Atlanta', 'limit' => 1],
                ['magic' => 'Montreal', 'limit' => 1],
                ['magic' => 'Los Angeles', 'limit' => 1],
                ['magic' => 'New York', 'limit' => 1],
                ['magic' => 'Seattle', 'limit' => 1],
                ['magic' => 'Santiago', 'limit' => 1],
                ['magic' => 'Sao Paulo', 'limit' => 1],
                ['magic' => 'Toronto', 'limit' => 1]
            ]
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: CyberJagrithi-Auditor'
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);

        if (!$response) return [];
        $data = json_decode($response, true);
        if (empty($data['id'])) return [];

        $measurementId = $data['id'];
        
        // Wait and poll (max 5 times, 1.5s apart)
        for ($i = 0; $i < 5; $i++) {
            usleep(1500000); // 1.5s
            
            $ch2 = curl_init('https://api.globalping.io/v1/measurements/' . $measurementId);
            curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch2, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch2, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            curl_setopt($ch2, CURLOPT_HTTPHEADER, [
                'Accept: application/json',
                'User-Agent: CyberJagrithi-Auditor'
            ]);
            $res2 = curl_exec($ch2);
            curl_close($ch2);
            
            if ($res2) {
                $data2 = json_decode($res2, true);
                if (isset($data2['status']) && $data2['status'] === 'finished') {
                    return $this->formatGlobalResults($data2['results']);
                }
            }
        }
        
        // Fallback: fetch whatever is ready
        $ch3 = curl_init('https://api.globalping.io/v1/measurements/' . $measurementId);
        curl_setopt($ch3, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch3, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch3, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_setopt($ch3, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'User-Agent: CyberJagrithi-Auditor'
        ]);
        $res3 = curl_exec($ch3);
        curl_close($ch3);
        if ($res3) {
            $data3 = json_decode($res3, true);
            if (!empty($data3['results'])) {
                return $this->formatGlobalResults($data3['results']);
            }
        }

        return [];
    }

    private function formatGlobalResults($rawResults) {
        $formatted = [];
        $regionMap = [
            'NA' => 'North America',
            'EU' => 'Europe',
            'AS' => 'Asia',
            'OC' => 'Oceania',
            'SA' => 'South America',
            'AF' => 'Africa'
        ];

        foreach ($rawResults as $r) {
            if (empty($r['result']['stats'])) continue;
            
            $probe = $r['probe'] ?? [];
            $stats = $r['result']['stats'] ?? [];
            
            $continentCode = $probe['continent'] ?? 'Other';
            $regionName = $regionMap[$continentCode] ?? 'Other';
            $country = $probe['country'] ?? 'Unknown';
            $city = $probe['city'] ?? 'Unknown';
            
            $formatted[] = [
                'location' => "$city, $country",
                'region' => $regionName,
                'ip_address' => $r['result']['resolvedAddress'] ?? 'Unknown',
                'status' => ($stats['loss'] ?? 100) < 100 ? 'alive' : 'dead',
                'packet_loss' => ($stats['loss'] ?? 100) . '%',
                'min_time' => $stats['min'] ?? '-',
                'max_time' => $stats['max'] ?? '-',
                'avg_time' => $stats['avg'] ?? '-',
                'lat' => $probe['latitude'] ?? null,
                'lon' => $probe['longitude'] ?? null
            ];
        }
        return $formatted;
    }

    private function execPing($host) {
        $isWin = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $cmd = $isWin ? "ping -n 4 " . escapeshellarg($host) : "ping -c 4 " . escapeshellarg($host);
        exec($cmd . " 2>&1", $out, $ret);
        $res = ['success' => false, 'avg' => 0, 'min' => 0, 'max' => 0, 'loss' => 100];
        $full = implode("\n", $out);
        if ($ret === 0 && (strpos($full, 'Reply') || strpos($full, 'bytes from'))) {
            $res['success'] = true;
            if ($isWin) {
                if (preg_match('/Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms/i', $full, $m)) {
                    $res['min'] = $m[1]; $res['max'] = $m[2]; $res['avg'] = $m[3];
                }
            } else {
                if (preg_match('/min\/avg\/max\/mdev\s*=\s*([\d.]+)\/([\d.]+)\/([\d.]+)/i', $full, $m)) {
                    $res['min'] = $m[1]; $res['avg'] = $m[2]; $res['max'] = $m[3];
                }
            }
            if (preg_match('/(\d+)% loss/i', $full, $m)) $res['loss'] = $m[1];
        }
        return $res;
    }

    private function tcpPing($host) {
        $start = microtime(true);
        $fp = @fsockopen($host, 80, $err, $errs, 2.0);
        if ($fp) { fclose($fp); return ['success' => true, 'ms' => round((microtime(true) - $start) * 1000, 2)]; }
        return ['success' => false, 'ms' => 0];
    }
}
?>