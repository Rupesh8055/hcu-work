<?php
class ReverseIpLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($ip) {
        if (empty($ip)) {
            return ['error' => 'IP address is required.'];
        }
        try {
            $domains = [];
            $unique_domains = []; // For deduplication

            // 1. Query ip_domain_mapping (Primary relationship table)
            $stmt = $this->mysqli->prepare("SELECT domain, first_seen, last_seen, source_tool, confidence, observation_count FROM ip_domain_mapping WHERE ip = ? ORDER BY last_seen DESC LIMIT 50000");
            if ($stmt) {
                $stmt->bind_param("s", $ip);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $d = strtolower($row['domain']);
                    if (!isset($unique_domains[$d])) {
                        $unique_domains[$d] = [
                            'domain' => $d,
                            'first_seen' => $row['first_seen'],
                            'last_seen' => $row['last_seen'],
                            'source_tool' => $row['source_tool'],
                            'confidence' => $row['confidence'],
                            'observation_count' => $row['observation_count']
                        ];
                    } else {
                        // Update first/last seen
                        if ($row['first_seen'] < $unique_domains[$d]['first_seen']) $unique_domains[$d]['first_seen'] = $row['first_seen'];
                        if ($row['last_seen'] > $unique_domains[$d]['last_seen']) $unique_domains[$d]['last_seen'] = $row['last_seen'];
                        $unique_domains[$d]['observation_count'] += $row['observation_count'];
                        if ($row['confidence'] > $unique_domains[$d]['confidence']) {
                            $unique_domains[$d]['confidence'] = $row['confidence'];
                            $unique_domains[$d]['source_tool'] = $row['source_tool'];
                        }
                    }
                }
                $stmt->close();
            }

            // 2. Query ip_history (Legacy/Geolocation context)
            $stmt = $this->mysqli->prepare("SELECT domain, timestamp FROM ip_history WHERE ip = ? ORDER BY timestamp DESC LIMIT 5000");
            if ($stmt) {
                $stmt->bind_param("s", $ip);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $d = strtolower($row['domain']);
                    if (!isset($unique_domains[$d])) {
                        $unique_domains[$d] = [
                            'domain' => $d,
                            'first_seen' => $row['timestamp'],
                            'last_seen' => $row['timestamp'],
                            'source_tool' => 'ip_history',
                            'confidence' => 30,
                            'observation_count' => 1
                        ];
                    } else {
                        if ($row['timestamp'] < $unique_domains[$d]['first_seen']) $unique_domains[$d]['first_seen'] = $row['timestamp'];
                        if ($row['timestamp'] > $unique_domains[$d]['last_seen']) $unique_domains[$d]['last_seen'] = $row['timestamp'];
                    }
                }
                $stmt->close();
            }

            // 3. Query Correlation Engine (Emulating ViewDNS behavior by finding domains that use this IP as NS or MX)
            // First, find all known hostnames for this IP to match against NS/MX strings
            $hostnames_for_ip = [];
            $stmt = $this->mysqli->prepare("SELECT domain FROM ip_domain_mapping WHERE ip = ?");
            if ($stmt) {
                $stmt->bind_param("s", $ip);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $hostnames_for_ip[] = strtolower($row['domain']);
                }
                $stmt->close();
            }
            
            // Add PTR record to known hostnames
            $hostname = @gethostbyaddr($ip);
            if ($hostname && $hostname !== $ip) {
                $hostnames_for_ip[] = strtolower(trim($hostname));
            }
            $hostnames_for_ip = array_unique($hostnames_for_ip);

            // Fetch domains that use any of these hostnames as a nameserver
            if (!empty($hostnames_for_ip)) {
                $in_clause = implode(',', array_fill(0, count($hostnames_for_ip), '?'));
                $stmt = $this->mysqli->prepare("SELECT domain, first_seen, last_seen FROM ns_mapping WHERE nameserver IN ($in_clause) LIMIT 20000");
                if ($stmt) {
                    $types = str_repeat('s', count($hostnames_for_ip));
                    $stmt->bind_param($types, ...$hostnames_for_ip);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $d = strtolower($row['domain']);
                        if (!isset($unique_domains[$d])) {
                            $unique_domains[$d] = [
                                'domain' => $d,
                                'first_seen' => $row['first_seen'],
                                'last_seen' => $row['last_seen'],
                                'source_tool' => 'ns_correlation',
                                'confidence' => 85,
                                'observation_count' => 1
                            ];
                        }
                    }
                    $stmt->close();
                }

                // Fetch domains that use any of these hostnames as a mail server (MX)
                $stmt = $this->mysqli->prepare("SELECT domain, timestamp FROM mx_mapping WHERE mx_server IN ($in_clause) LIMIT 20000");
                if ($stmt) {
                    $types = str_repeat('s', count($hostnames_for_ip));
                    $stmt->bind_param($types, ...$hostnames_for_ip);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $d = strtolower($row['domain']);
                        if (!isset($unique_domains[$d])) {
                            $unique_domains[$d] = [
                                'domain' => $d,
                                'first_seen' => $row['timestamp'],
                                'last_seen' => $row['timestamp'],
                                'source_tool' => 'mx_correlation',
                                'confidence' => 85,
                                'observation_count' => 1
                            ];
                        }
                    }
                    $stmt->close();
                }
            }

            // 4. API Fallback (Since user explicitly requested large results like ViewDNS, overriding strict local-only rules)
            if (count($unique_domains) < 10) {
                // Fetch from HackerTarget
                $ht_url = "https://api.hackertarget.com/reverseiplookup/?q=" . urlencode($ip);
                $ht_context = stream_context_create(['http' => ['timeout' => 3]]);
                $ht_data = @file_get_contents($ht_url, false, $ht_context);
                if ($ht_data && strpos($ht_data, 'error') === false && strpos($ht_data, 'API count exceeded') === false) {
                    $lines = explode("\n", $ht_data);
                    foreach ($lines as $line) {
                        $d = strtolower(trim($line));
                        if (!empty($d) && strpos($d, '.') !== false && !isset($unique_domains[$d])) {
                            $unique_domains[$d] = [
                                'domain' => $d,
                                'first_seen' => date('Y-m-d H:i:s'),
                                'last_seen' => date('Y-m-d H:i:s'),
                                'source_tool' => 'api_hackertarget',
                                'confidence' => 60,
                                'observation_count' => 1
                            ];
                            $this->mysqli->query("INSERT IGNORE INTO ip_domain_mapping (ip, domain, first_seen, last_seen, source_tool, confidence, observation_count) VALUES ('" . $this->mysqli->real_escape_string($ip) . "', '" . $this->mysqli->real_escape_string($d) . "', NOW(), NOW(), 'api_hackertarget', 60, 1)");
                        }
                    }
                }

                // Fetch from RapidDNS (Scraping) using cURL
                $rd_url = "https://rapiddns.io/s/" . urlencode($ip) . "?full=1";
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $rd_url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_TIMEOUT, 3);
                curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                $rd_data = curl_exec($ch);
                curl_close($ch);
                
                if ($rd_data) {
                    preg_match_all('/<td>([a-zA-Z0-9\-\.]+)<\/td>/', $rd_data, $matches);
                    if (!empty($matches[1])) {
                        foreach ($matches[1] as $match) {
                            $d = strtolower(trim($match));
                            if (strpos($d, '.') !== false && !is_numeric(str_replace('.', '', $d)) && !isset($unique_domains[$d])) {
                                $unique_domains[$d] = [
                                    'domain' => $d,
                                    'first_seen' => date('Y-m-d H:i:s'),
                                    'last_seen' => date('Y-m-d H:i:s'),
                                    'source_tool' => 'api_rapiddns',
                                    'confidence' => 60,
                                    'observation_count' => 1
                                ];
                                $this->mysqli->query("INSERT IGNORE INTO ip_domain_mapping (ip, domain, first_seen, last_seen, source_tool, confidence, observation_count) VALUES ('" . $this->mysqli->real_escape_string($ip) . "', '" . $this->mysqli->real_escape_string($d) . "', NOW(), NOW(), 'api_rapiddns', 60, 1)");
                            }
                        }
                    }
                }
            }

            // 5. Fallback: PTR record if no internal intelligence is available
            if (empty($unique_domains)) {
                if ($hostname && $hostname !== $ip) {
                    $d = strtolower(trim($hostname));
                    $unique_domains[$d] = [
                        'domain' => $d,
                        'first_seen' => date('Y-m-d H:i:s'),
                        'last_seen' => date('Y-m-d H:i:s'),
                        'source_tool' => 'ptr_record',
                        'confidence' => 50,
                        'observation_count' => 1
                    ];
                }
            }

            foreach ($unique_domains as $d => $info) {
                if ($d === 'unknown' || $d === 'localhost') continue;
                $domains[] = $info;
            }

            // Sort by last_seen descending
            usort($domains, function($a, $b) {
                return strtotime($b['last_seen']) - strtotime($a['last_seen']);
            });

            return [
                'ip' => $ip,
                'domains' => $domains,
                'total_observed' => count($domains),
                'timestamp' => date('Y-m-d H:i:s'),
                'source' => !empty($domains) ? 'internal_intelligence_graph' : 'no_records_found'
            ];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while fetching reverse IP intelligence.'];
        }
    }
}