<?php
class DnsLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($domain, $type = 'ANY') {
        if (empty($domain)) return ['error' => 'Domain is required.'];
        $type = strtoupper($type);
        
        $typeMap = [
            'A' => 1, 'AAAA' => 28, 'MX' => 15, 'NS' => 2,
            'TXT' => 16, 'CNAME' => 5, 'SOA' => 6, 'CAA' => 257, 'ANY' => 255
        ];
        $dnsType = $typeMap[$type] ?? 255;
        
        try {
            // Using Google DoH API for robust lookups, bypassing Windows dns_get_record issues
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://dns.google/resolve?name=" . urlencode($domain) . "&type=" . $dnsType);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $res = curl_exec($ch);
            curl_close($ch);

            if (!$res) return ['error' => 'DNS lookup failed via API.'];
            $data = json_decode($res, true);
            if (!isset($data['Answer'])) {
                // If specific type fails, return empty records instead of failing totally
                $records = [];
            } else {
                $records = [];
                foreach ($data['Answer'] as $ans) {
                    $strType = array_search($ans['type'], $typeMap);
                    if (!$strType) $strType = 'UNKNOWN (' . $ans['type'] . ')';
                    
                    $r = [
                        'host' => rtrim($ans['name'], '.'),
                        'class' => 'IN',
                        'ttl' => $ans['TTL'],
                        'type' => $strType,
                        'data' => $ans['data'] // Original raw data
                    ];
                    
                    // Map fields for compatibility with accumulateDnsIntelligence and UI
                    if ($strType === 'A') $r['ip'] = $ans['data'];
                    if ($strType === 'AAAA') $r['ipv6'] = $ans['data'];
                    if ($strType === 'TXT') $r['txt'] = trim($ans['data'], '"');
                    if ($strType === 'NS' || $strType === 'CNAME') {
                        $r['target'] = rtrim($ans['data'], '.');
                    }
                    if ($strType === 'MX') {
                        $parts = explode(' ', $ans['data'], 2);
                        $r['pri'] = $parts[0] ?? 0;
                        $r['target'] = rtrim($parts[1] ?? '', '.');
                    }
                    $records[] = $r;
                }
            }

            // Store nameservers for Reverse NS dataset building
            $nsList = [];
            foreach ($records as $r) {
                if (($r['type'] ?? '') === 'NS' && isset($r['target'])) {
                    $nsList[] = $r['target'];
                }
            }
            if (!empty($nsList)) {
                require_once __DIR__ . '/../Includes/DatabaseManager.php';
                DatabaseManager::storeNameservers($this->mysqli, $domain, $nsList);
                DatabaseManager::saveNsSnapshot($this->mysqli, $domain, $nsList);
            }

            // Accumulate progressive DNS intelligence
            require_once __DIR__ . '/../Includes/DatabaseManager.php';
            DatabaseManager::accumulateDnsIntelligence($this->mysqli, $domain, $records);
            
            // Format records for UI display and snapshotting
            $results = [];
            foreach ($records as $r) {
                $results[] = [
                    'host' => $r['host'] ?? '',
                    'class' => $r['class'] ?? 'IN',
                    'ttl' => $r['ttl'] ?? 0,
                    'type' => $r['type'] ?? '',
                    'data' => $this->formatDnsData($r)
                ];
            }

            // Save DNS snapshot for historical timeline tracking
            DatabaseManager::saveDnsSnapshot($this->mysqli, $domain, $type, $results);

            // Fetch historical DNS snapshot timeline for this domain
            $history = [
                'dns' => [],
                'nameservers' => []
            ];
            $stmt = $this->mysqli->prepare("SELECT record_type, record_data, timestamp FROM dns_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 20");
            if ($stmt) {
                $stmt->bind_param('s', $domain);
                $stmt->execute();
                $resDb = $stmt->get_result();
                while ($row = $resDb->fetch_assoc()) {
                    $history['dns'][] = [
                        'type' => $row['record_type'],
                        'data' => json_decode($row['record_data'], true) ?? $row['record_data'],
                        'timestamp' => $row['timestamp']
                    ];
                }
                $stmt->close();
            }

            // Fetch nameserver snapshots
            $stmt = $this->mysqli->prepare("SELECT nameservers, timestamp FROM ns_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 20");
            if ($stmt) {
                $stmt->bind_param('s', $domain);
                $stmt->execute();
                $resDb = $stmt->get_result();
                while ($row = $resDb->fetch_assoc()) {
                    $history['nameservers'][] = [
                        'nameservers' => explode(',', $row['nameservers']),
                        'timestamp' => $row['timestamp']
                    ];
                }
                $stmt->close();
            }

            $intelligence = $this->gatherIntelligence($domain, $records);

            return [
                'domain' => $domain,
                'type' => $type,
                'records' => $results,
                'intelligence' => $intelligence,
                'history' => $history,
                'timestamp' => date('Y-m-d H:i:s'),
                'source' => 'google_doh_api'
            ];
        } catch (Exception $e) {
            return ['error' => 'An error occurred during DNS lookup.'];
        }
    }
    private function gatherIntelligence($domain, $records) {
        $intel = [
            'spf_record' => false,
            'dmarc_record' => false,
            'dkim_records' => [],
            'cname_chain' => []
        ];
        foreach ($records as $r) {
            if ($r['type'] === 'TXT') {
                $txt = $r['txt'] ?? $r['data'];
                if (stripos($txt, 'v=spf1') !== false) $intel['spf_record'] = true;
            }
            if ($r['type'] === 'CNAME') {
                $intel['cname_chain'][] = ['from' => $r['host'], 'to' => $r['target'], 'type' => 'CNAME'];
            }
        }
        
        // Lookup DMARC explicitly using DoH
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://dns.google/resolve?name=_dmarc." . urlencode($domain) . "&type=16");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res) {
            $data = json_decode($res, true);
            if (isset($data['Answer'])) {
                $intel['dmarc_record'] = true;
            }
        }
        
        return $intel;
    }
    private function formatDnsData($r) {
        switch ($r['type']) {
            case 'A': return $r['ip'] ?? $r['data'];
            case 'AAAA': return $r['ipv6'] ?? $r['data'];
            case 'MX': return ($r['pri'] ?? '0') . ' ' . ($r['target'] ?? $r['data']);
            case 'TXT': return $r['txt'] ?? $r['data'];
            case 'SOA': return $r['data'];
            case 'CAA': return $r['data'];
            default: return $r['target'] ?? $r['data'];
        }
    }
}