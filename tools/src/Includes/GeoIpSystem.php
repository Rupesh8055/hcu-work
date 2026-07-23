<?php
require_once __DIR__ . '/../Models/WhoisLookupModel.php';

class GeoIpSystem {
    private $mysqli;
    private $cities;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $dataPath = __DIR__ . '/../Data/cities_lite.json';
        if (file_exists($dataPath)) {
            $this->cities = json_decode(file_get_contents($dataPath), true);
        } else {
            $this->cities = [];
        }
    }

    public function lookup($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return null;
        }
        $ipNum = sprintf('%u', $ipLong);

        // 1. Try checking the local highly-indexed ip_ranges table first (0ms offline lookup)
        $cachedRange = $this->lookupLocalRange($ipNum);
        if ($cachedRange) {
            $location = [
                'city' => 'Unknown',
                'country' => $cachedRange['country_code'] !== 'Unknown' ? $cachedRange['country_code'] : 'Unknown',
                'latitude' => 0,
                'longitude' => 0,
                'isp' => $cachedRange['isp_org'] !== 'Unknown' ? $cachedRange['isp_org'] : 'Unknown',
                'organization' => $cachedRange['isp_org'] !== 'Unknown' ? $cachedRange['isp_org'] : 'Unknown',
                'asn' => $cachedRange['asn'] ?? null,
                'registry' => $cachedRange['registry'] ?? 'Unknown',
                'source' => 'local_range_database'
            ];

            // Map City/Country coordinates
            $this->mapCoordinates($location);
            return $location;
        }

        // 2. Fallback to WHOIS Parsing (Allowed live TCP/UDP socket query)
        $whoisModel = new WhoisLookupModel($this->mysqli);
        $whoisData = $whoisModel->lookup($ip);
        
        $location = [
            'city' => 'Unknown',
            'country' => 'Unknown',
            'latitude' => 0,
            'longitude' => 0,
            'isp' => 'Unknown',
            'organization' => 'Unknown',
            'asn' => null,
            'registry' => 'Unknown',
            'source' => 'local_whois_parsing'
        ];

        $raw = '';
        if (isset($whoisData['raw']) || isset($whoisData['full_record'])) {
            $raw = $whoisData['raw'] ?? ($whoisData['full_record'] ?? '');
        }

        if (!empty($raw)) {
            // Extract Country
            if (preg_match('/country:\s*([A-Z]{2})/i', $raw, $m)) {
                $location['country'] = strtoupper(trim($m[1]));
            }
            
            // Extract City
            if (preg_match('/city:\s*([a-zA-Z\s.-]+)/i', $raw, $m)) {
                $cityVal = trim($m[1]);
                if (strcasecmp($cityVal, 'unknown') !== 0) {
                    $location['city'] = $cityVal;
                }
            }
            
            // Extract ISP/Org
            if (preg_match('/descr:\s*(.+)/i', $raw, $m)) {
                $location['isp'] = trim($m[1]);
            }
            if (preg_match('/orgname:\s*(.+)/i', $raw, $m)) {
                $location['organization'] = trim($m[1]);
            } elseif (preg_match('/owner:\s*(.+)/i', $raw, $m)) {
                $location['organization'] = trim($m[1]);
            }
            
            if ($location['organization'] !== 'Unknown' && $location['isp'] === 'Unknown') {
                $location['isp'] = $location['organization'];
            }
            if ($location['isp'] !== 'Unknown' && $location['organization'] === 'Unknown') {
                $location['organization'] = $location['isp'];
            }

            // Extract ASN
            if (preg_match('/origin:\s*AS([0-9]+)/i', $raw, $m)) {
                $location['asn'] = (int)$m[1];
            } elseif (preg_match('/asn:\s*([0-9]+)/i', $raw, $m)) {
                $location['asn'] = (int)$m[1];
            }

            // Extract Registry
            if (preg_match('/source:\s*(.+)/i', $raw, $m)) {
                $location['registry'] = strtoupper(trim($m[1]));
            }

            // Extract Subnet CIDR / range
            $cidrStr = '';
            if (preg_match('/inetnum:\s*(.+)/i', $raw, $m)) {
                $cidrStr = trim($m[1]);
            } elseif (preg_match('/route:\s*(.+)/i', $raw, $m)) {
                $cidrStr = trim($m[1]);
            } elseif (preg_match('/NetRange:\s*(.+)/i', $raw, $m)) {
                $cidrStr = trim($m[1]);
            } elseif (preg_match('/CIDR:\s*(.+)/i', $raw, $m)) {
                $cidrStr = trim($m[1]);
            }

            // Progressive Self-Learning: Parse range and store back in the local ip_ranges index!
            if (!empty($cidrStr)) {
                $range = $this->parseIpRangeOrCidr($cidrStr);
                if ($range && $location['country'] !== 'Unknown') {
                    $this->saveLocalRange($range['start'], $range['end'], $range['cidr'], $location['country'], $location['asn'], $location['organization'], $location['registry']);
                }
            }
        }

        // 3. Map Coordinates
        $this->mapCoordinates($location);

        return $location;
    }

    private function lookupLocalRange($ipNum) {
        if (!$this->mysqli) return null;
        
        $sql = "SELECT cidr, country_code, asn, isp_org, registry FROM ip_ranges 
                WHERE ? >= start_ip_num AND ? <= end_ip_num 
                LIMIT 1";
        $stmt = $this->mysqli->prepare($sql);
        if ($stmt) {
            $stmt->bind_param('ss', $ipNum, $ipNum);
            $stmt->execute();
            $res = $stmt->get_result();
            $row = $res->fetch_assoc();
            $stmt->close();
            return $row;
        }
        return null;
    }

    private function saveLocalRange($start, $end, $cidr, $cc, $asn, $org, $registry) {
        if (!$this->mysqli) return false;
        
        $sql = "INSERT INTO ip_ranges (start_ip_num, end_ip_num, cidr, country_code, asn, isp_org, registry) 
                VALUES (?, ?, ?, ?, ?, ?, ?) 
                ON DUPLICATE KEY UPDATE country_code = VALUES(country_code), asn = VALUES(asn), isp_org = VALUES(isp_org), registry = VALUES(registry)";
        $stmt = $this->mysqli->prepare($sql);
        if ($stmt) {
            $stmt->bind_param('ssssiss', $start, $end, $cidr, $cc, $asn, $org, $registry);
            $success = $stmt->execute();
            $stmt->close();
            return $success;
        }
        return false;
    }

    /**
     * Highly robust utility to convert a CIDR subnet or range string into start and end unsigned integers.
     */
    public function parseIpRangeOrCidr($input) {
        $input = trim($input);
        if (empty($input)) return null;

        // Clean any comments or spaces inside ranges
        $input = preg_replace('/\s+/', ' ', $input);

        // Check if it's a CIDR like 192.168.1.0/24 or a list of them
        if (strpos($input, '/') !== false) {
            // Pick first CIDR if multiple listed
            if (preg_match('/([0-9.]+)\/([0-9]+)/', $input, $m)) {
                $subnet = $m[1];
                $bits = (int)$m[2];
                $ipLong = ip2long($subnet);
                if ($ipLong === false || $bits < 0 || $bits > 32) return null;
                
                $mask = ~((1 << (32 - $bits)) - 1);
                if ($bits === 0) $mask = 0; // handle /0 boundary
                
                $start = $ipLong & $mask;
                $end = $start | ~($mask);
                
                return [
                    'start' => sprintf('%u', $start),
                    'end' => sprintf('%u', $end),
                    'cidr' => $subnet . '/' . $bits
                ];
            }
        }

        // Check if it's a range like 192.168.1.0 - 192.168.1.255
        if (strpos($input, '-') !== false) {
            $parts = explode('-', $input);
            if (count($parts) === 2) {
                $startIp = trim($parts[0]);
                $endIp = trim($parts[1]);
                $startLong = ip2long($startIp);
                $endLong = ip2long($endIp);
                if ($startLong !== false && $endLong !== false) {
                    return [
                        'start' => sprintf('%u', $startLong),
                        'end' => sprintf('%u', $endLong),
                        'cidr' => $startIp . '-' . $endIp
                    ];
                }
            }
        }

        // Single IP fallback
        $ipLong = ip2long($input);
        if ($ipLong !== false) {
            return [
                'start' => sprintf('%u', $ipLong),
                'end' => sprintf('%u', $ipLong),
                'cidr' => $input . '/32'
            ];
        }

        return null;
    }

    private function mapCoordinates(&$location) {
        if ($location['city'] !== 'Unknown' && isset($this->cities[$location['city']])) {
            $location['latitude'] = $this->cities[$location['city']]['lat'];
            $location['longitude'] = $this->cities[$location['city']]['lon'];
        } elseif ($location['country'] !== 'Unknown' && isset($this->cities[$location['country']])) {
            $location['latitude'] = $this->cities[$location['country']]['lat'];
            $location['longitude'] = $this->cities[$location['country']]['lon'];
        }
    }
}
