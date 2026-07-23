<?php
require_once __DIR__ . '/../Includes/GeoIpSystem.php';

class IpHistoryModel {
    private $mysqli;
    private $geoSystem;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->geoSystem = new GeoIpSystem($mysqli);
    }

    public function getHistory($query, $limit = 500, $offset = 0) {
        if (empty($query)) return [];
        $query = strtolower(trim($query));
        $isIp = filter_var($query, FILTER_VALIDATE_IP);
        
        try {
            // 1. Process current query to build history
            if (!$isIp) {
                $domain = $query;
                $aRecords = @dns_get_record($domain, DNS_A);
                if ($aRecords) {
                    foreach ($aRecords as $record) {
                        if (isset($record['ip'])) {
                            $this->saveEntry($domain, $record['ip'], 'live_query');
                        }
                    }
                }
            } else {
                // If IP searched, try to get PTR or just save it
                $ptr = @gethostbyaddr($query);
                $domain = ($ptr && $ptr !== $query) ? $ptr : 'unknown';
                $this->saveEntry($domain, $query, 'live_query');
            }

            // 2. Fetch history from database
            $history = [];

            if ($this->mysqli) {
                if ($isIp) {
                    $stmt = $this->mysqli->prepare("SELECT * FROM ip_history WHERE ip_address = ? ORDER BY last_seen DESC LIMIT ? OFFSET ?");
                } else {
                    $stmt = $this->mysqli->prepare("SELECT * FROM ip_history WHERE domain = ? ORDER BY last_seen DESC LIMIT ? OFFSET ?");
                }
                
                if ($stmt) {
                    $stmt->bind_param('sii', $query, $limit, $offset);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        // Format dates for UI
                        $row['first_seen'] = date('Y-m-d H:i:s', strtotime($row['first_seen']));
                        $row['last_seen'] = date('Y-m-d H:i:s', strtotime($row['last_seen']));
                        $history[] = $row;
                    }
                    $stmt->close();
                }
            }

            return $history;
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    public function getHistoryCount($query) {
        if (empty($query)) return 0;
        $query = strtolower(trim($query));
        $isIp = filter_var($query, FILTER_VALIDATE_IP);
        
        if ($this->mysqli) {
            if ($isIp) {
                $stmt = $this->mysqli->prepare("SELECT COUNT(*) FROM ip_history WHERE ip_address = ?");
            } else {
                $stmt = $this->mysqli->prepare("SELECT COUNT(*) FROM ip_history WHERE domain = ?");
            }
            if ($stmt) {
                $stmt->bind_param('s', $query);
                $stmt->execute();
                $stmt->bind_result($count);
                if($stmt->fetch()) {
                    $stmt->close();
                    return $count;
                }
                $stmt->close();
            }
        }
        return 0;
    }

    public function saveEntry($domain, $ip, $source = 'dns_lookup') {
        // Get Geo info
        $locData = $this->geoSystem->lookup($ip);
        $country = 'Unknown';
        $owner = 'Unknown';
        $asn = 'Unknown';
        
        if ($locData) {
            $country = $locData['country'] ?? 'Unknown';
            $owner = $locData['organization'] ?? 'Unknown';
            $asn = $locData['asn'] ?? 'Unknown';
        }

        // If owner is still unknown, try a quick WHOIS if it's a public IP
        if ($owner === 'Unknown' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $owner = $this->fetchOwnerViaWhois($ip);
        }

        // Fetch nameservers at that time
        $ns_records = @dns_get_record($domain, DNS_NS);
        $nameservers = [];
        if ($ns_records) {
            foreach($ns_records as $ns) {
                if(isset($ns['target'])) $nameservers[] = $ns['target'];
            }
        }
        $ns_str = !empty($nameservers) ? implode(',', $nameservers) : null;

        // Check latest record
        $stmt = $this->mysqli->prepare("SELECT id, ip_address FROM ip_history WHERE domain = ? ORDER BY last_seen DESC LIMIT 1");
        $latestId = null;
        $latestIp = null;
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $stmt->bind_result($latestId, $latestIp);
            $stmt->fetch();
            $stmt->close();
        }

        if ($latestId && $latestIp === $ip) {
            // Update last_seen and observation_count
            $update = $this->mysqli->prepare("UPDATE ip_history SET last_seen = NOW(), observation_count = observation_count + 1 WHERE id = ?");
            if ($update) {
                $update->bind_param('i', $latestId);
                $update->execute();
                $update->close();
            }
        } else {
            // Insert new record
            $insert = $this->mysqli->prepare("INSERT INTO ip_history (domain, ip_address, asn, organization, country, nameservers_at_that_time, source, first_seen, last_seen, observation_count) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1)");
            if ($insert) {
                $insert->bind_param('sssssss', $domain, $ip, $asn, $owner, $country, $ns_str, $source);
                $insert->execute();
                $insert->close();
            }
        }
    }

    private function fetchOwnerViaWhois($ip) {
        $ipNum = sprintf('%u', ip2long($ip));
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT isp_org FROM ip_ranges WHERE ? >= start_ip_num AND ? <= end_ip_num LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('ss', $ipNum, $ipNum);
                $stmt->execute();
                $stmt->bind_result($dbOrg);
                if ($stmt->fetch()) {
                    $stmt->close();
                    if (!empty($dbOrg) && $dbOrg !== 'Unknown') return $dbOrg;
                } else {
                    $stmt->close();
                }
            }
        }

        $servers = ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net'];
        foreach ($servers as $server) {
            $fp = @fsockopen($server, 43, $errno, $errstr, 2);
            if (!$fp) continue;
            stream_set_timeout($fp, 2);
            fwrite($fp, $ip . "\r\n");
            $out = '';
            while (!feof($fp)) {
                $info = stream_get_meta_data($fp);
                if ($info['timed_out']) break;
                $out .= fgets($fp, 1024);
            }
            fclose($fp);
            
            if (!empty($out)) {
                $patterns = ['/OrgName:\s*(.+)/i', '/Organization:\s*(.+)/i', '/descr:\s*(.+)/i'];
                foreach ($patterns as $p) {
                    if (preg_match($p, $out, $m)) return trim($m[1]);
                }
            }
        }
        return 'Unknown';
    }
}