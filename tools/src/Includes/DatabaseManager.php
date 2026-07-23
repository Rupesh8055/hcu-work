<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/GeoIpSystem.php';

class DatabaseManager {
    private static $expiry_days = 10;

    public static function logRequest($mysqli, $tool, $input, $error = null) {
        if (function_exists('log_lookup_v4')) {
            log_lookup_v4($mysqli, $tool, $input, $error);
        }
    }

    /**
     * Checks database cache with active concurrency protection locks.
     */
    public static function checkCache($mysqli, $tool, $input) {
        if (!$mysqli) return ['status' => 'miss', 'data' => null];

        $sql = "SELECT result_data, status, last_updated FROM tool_results WHERE tool_name = ? AND input_query = ? LIMIT 1";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) return ['status' => 'miss', 'data' => null];

        $stmt->bind_param('ss', $tool, $input);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if (!$row) return ['status' => 'miss', 'data' => null];

        $data = json_decode($row['result_data'], true);
        $last_updated = $row['last_updated'];
        $db_status = $row['status'];

        // Concurrency Protection: Check for active 'refreshing' lock (last 60 seconds)
        if ($db_status === 'refreshing') {
            $is_lock_active = (time() - strtotime($last_updated)) < 60;
            if ($is_lock_active) {
                // Serve stale cache to deduplicate parallel requests and avoid race conditions
                return ['status' => 'hit', 'data' => $data, 'last_updated' => $last_updated, 'refreshing' => true];
            }
        }

        $is_expired = (time() - strtotime($last_updated)) > (self::$expiry_days * 86400);
        if ($is_expired || $db_status === 'expired') {
            return ['status' => 'stale', 'data' => $data, 'last_updated' => $last_updated];
        }

        return ['status' => 'hit', 'data' => $data, 'last_updated' => $last_updated];
    }

    /**
     * Atomically stores a tool resolution result and releases concurrency locks.
     */
    public static function storeResult($mysqli, $tool, $input, $data, $status = 'fresh') {
        if (!$mysqli) return false;
        
        $json_data = json_encode($data);
        $sql = "INSERT INTO tool_results (tool_name, input_query, result_data, status, last_updated) 
                VALUES (?, ?, ?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE result_data = VALUES(result_data), status = VALUES(status), last_updated = NOW()";
        
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) return false;

        $stmt->bind_param('ssss', $tool, $input, $json_data, $status);
        $success = $stmt->execute();
        $stmt->close();
        return $success;
    }

    /**
     * Sets status to refreshing to acquire an atomic execution lock.
     */
    public static function markRefreshing($mysqli, $tool, $input) {
        if (!$mysqli) return false;
        
        // If row doesn't exist, insert a placeholder refreshing lock row
        $sqlInsert = "INSERT IGNORE INTO tool_results (tool_name, input_query, result_data, status, last_updated) 
                      VALUES (?, ?, NULL, 'refreshing', NOW())";
        $stmtInsert = $mysqli->prepare($sqlInsert);
        if ($stmtInsert) {
            $stmtInsert->bind_param('ss', $tool, $input);
            $stmtInsert->execute();
            $stmtInsert->close();
        }

        $sql = "UPDATE tool_results 
                SET status = 'refreshing', last_updated = NOW() 
                WHERE tool_name = ? AND input_query = ? AND (status = 'fresh' OR status = 'expired' OR status = 'refreshing')";
        
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) return false;

        $stmt->bind_param('ss', $tool, $input);
        $stmt->execute();
        $affected = $stmt->affected_rows;
        $stmt->close();
        return $affected > 0;
    }

    public static function triggerBackgroundRefresh($tool, $input) {
        global $mysqli;
        if (!$mysqli) return false;
        
        // 1. Prevent duplicate concurrent runs for the same query/tool
        $stmtCheck = $mysqli->prepare("SELECT id FROM scan_queue WHERE tool_name = ? AND input_query = ? AND (status = 'pending' OR status = 'processing') LIMIT 1");
        if ($stmtCheck) {
            $stmtCheck->bind_param('ss', $tool, $input);
            $stmtCheck->execute();
            $stmtCheck->store_result();
            $cnt = $stmtCheck->num_rows;
            $stmtCheck->close();
            if ($cnt > 0) return true; // Already actively queued or running
        }

        // 2. Insert new high-priority queue job (Priority: 10)
        $stmt = $mysqli->prepare("INSERT INTO scan_queue (tool_name, input_query, priority, status) VALUES (?, ?, 10, 'pending')");
        if ($stmt) {
            $stmt->bind_param('ss', $tool, $input);
            $success = $stmt->execute();
            $stmt->close();
            
            // 3. Trigger the queue daemon execution in the background asynchronously
            $phpPath = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? 'c:\xampp\php\php.exe' : 'php');
            $daemonPath = TOOLS_ROOT . '/src/Scripts/queue_daemon.php';
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $cmd = "start /B " . escapeshellarg($phpPath) . " " . escapeshellarg($daemonPath) . " > NUL 2>&1";
                pclose(popen($cmd, "r"));
            } else {
                $cmd = escapeshellcmd($phpPath) . " " . escapeshellarg($daemonPath) . " > /dev/null 2>&1 &";
                exec($cmd);
            }
            
            return $success;
        }
        return false;
    }

    public static function storeNameservers($mysqli, $domain, $nsList) {
        if (!$mysqli || empty($domain) || empty($nsList)) return false;
        $domain = strtolower(trim($domain));
        
        $stmt = $mysqli->prepare("INSERT INTO ns_mapping (domain, nameserver, first_seen, last_seen) VALUES (?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE last_seen = NOW()");
        if ($stmt) {
            foreach ($nsList as $ns) {
                $ns = strtolower(trim(rtrim($ns, '.')));
                if (!empty($ns)) {
                    $stmt->bind_param('ss', $domain, $ns);
                    $stmt->execute();
                }
            }
            $stmt->close();
            return true;
        }
        return false;
    }

    public static function storeIpDomainMapping($mysqli, $domain, $ip, $source_tool, $confidence = 50) {
        if (!$mysqli || empty($domain) || empty($ip) || $domain === 'unknown') return false;
        
        $stmt = $mysqli->prepare("INSERT INTO ip_domain_mapping (domain, ip, first_seen, last_seen, source_tool, confidence, observation_count) 
                                  VALUES (?, ?, NOW(), NOW(), ?, ?, 1) 
                                  ON DUPLICATE KEY UPDATE 
                                      last_seen = NOW(), 
                                      observation_count = observation_count + 1,
                                      source_tool = IF(VALUES(confidence) > confidence, VALUES(source_tool), source_tool),
                                      confidence = IF(VALUES(confidence) > confidence, VALUES(confidence), confidence)");
        if ($stmt) {
            $stmt->bind_param('sssi', $domain, $ip, $source_tool, $confidence);
            $stmt->execute();
            $stmt->close();
            return true;
        }
        return false;
    }

    /**
     * Progressive Intelligence Graph: Parses DNS A, MX, and NS records to grow the network graph.
     */
    public static function accumulateDnsIntelligence($mysqli, $domain, $records) {
        if (!$mysqli || empty($domain) || empty($records)) return false;
        $domain = strtolower(trim($domain));

        $aList = [];
        $nsList = [];
        $mxList = [];
        foreach ($records as $r) {
            $type = strtoupper($r['type'] ?? '');
            if ($type === 'A' && isset($r['ip'])) {
                $aList[] = $r['ip'];
            } elseif ($type === 'A' && isset($r['data']) && filter_var($r['data'], FILTER_VALIDATE_IP)) {
                $aList[] = $r['data'];
            } elseif ($type === 'NS' && isset($r['target'])) {
                $nsList[] = strtolower(trim(rtrim($r['target'], '.')));
            } elseif ($type === 'NS' && isset($r['data'])) {
                $nsList[] = strtolower(trim(rtrim($r['data'], '.')));
            } elseif ($type === 'MX' && isset($r['target'])) {
                $mxServer = strtolower(trim(rtrim($r['target'], '.')));
                $pri = (int)($r['pri'] ?? 0);
                if (!empty($mxServer)) {
                    $mxList[] = ['server' => $mxServer, 'priority' => $pri];
                }
            }
        }

        // 1. Store nameservers
        if (!empty($nsList)) {
            self::storeNameservers($mysqli, $domain, $nsList);
            foreach ($nsList as $ns) {
                if (filter_var($ns, FILTER_VALIDATE_IP)) {
                    self::storeIpDomainMapping($mysqli, $domain, $ns, 'dns_intelligence_ns', 60);
                } else {
                    $ip = @gethostbyname($ns);
                    if ($ip && $ip !== $ns && filter_var($ip, FILTER_VALIDATE_IP)) {
                        self::storeIpDomainMapping($mysqli, $domain, $ip, 'dns_intelligence_ns', 60);
                        self::accumulateIpIntelligence($mysqli, $ip);
                    }
                }
            }
        }

        // 2. Store MX mappings
        if (!empty($mxList)) {
            $stmt = $mysqli->prepare("INSERT INTO mx_mapping (domain, mx_server, priority) VALUES (?, ?, ?) 
                                      ON DUPLICATE KEY UPDATE priority = VALUES(priority), timestamp = NOW()");
            if ($stmt) {
                foreach ($mxList as $mx) {
                    $stmt->bind_param('ssi', $domain, $mx['server'], $mx['priority']);
                    $stmt->execute();
                    
                    $mxServ = $mx['server'];
                    if (filter_var($mxServ, FILTER_VALIDATE_IP)) {
                        self::storeIpDomainMapping($mysqli, $domain, $mxServ, 'dns_intelligence_mx', 60);
                    } else {
                        $ip = @gethostbyname($mxServ);
                        if ($ip && $ip !== $mxServ && filter_var($ip, FILTER_VALIDATE_IP)) {
                            self::storeIpDomainMapping($mysqli, $domain, $ip, 'dns_intelligence_mx', 60);
                            self::accumulateIpIntelligence($mysqli, $ip);
                        }
                    }
                }
                $stmt->close();
            }
        }

        // 3. Store Domain-IP pairs
        if (!empty($aList)) {
            $geo = new GeoIpSystem($mysqli);
            foreach ($aList as $ip) {
                $locData = $geo->lookup($ip);
                $location = 'Unknown';
                $owner = 'Unknown';
                if ($locData) {
                    $location = ($locData['city'] !== 'Unknown' ? $locData['city'] . ', ' : '') . $locData['country'];
                    $owner = $locData['organization'] !== 'Unknown' ? $locData['organization'] : ($locData['isp'] !== 'Unknown' ? $locData['isp'] : 'Unknown');
                }

                $stmt = $mysqli->prepare("INSERT INTO ip_history (domain, ip, timestamp, owner, location) 
                                          VALUES (?, ?, NOW(), ?, ?) 
                                          ON DUPLICATE KEY UPDATE owner = VALUES(owner), location = VALUES(location), timestamp = NOW()");
                if ($stmt) {
                    $stmt->bind_param('ssss', $domain, $ip, $owner, $location);
                    $stmt->execute();
                    $stmt->close();
                }
                
                self::storeIpDomainMapping($mysqli, $domain, $ip, 'dns_intelligence', 90);
            }
        }
        return true;
    }

    /**
     * Progressive Intelligence Graph: Automates PTR DNS lookup, ASN resolution, and geolocates any searched IP.
     */
    public static function accumulateIpIntelligence($mysqli, $ip) {
        if (!$mysqli || !filter_var($ip, FILTER_VALIDATE_IP)) return false;

        // 1. PTR lookup
        $hostname = @gethostbyaddr($ip);
        $domain = ($hostname && $hostname !== $ip) ? strtolower($hostname) : 'unknown';

        // 2. Geolocation lookup
        $geo = new GeoIpSystem($mysqli);
        $locData = $geo->lookup($ip);
        $location = 'Unknown';
        $owner = 'Unknown';
        if ($locData) {
            $location = ($locData['city'] !== 'Unknown' ? $locData['city'] . ', ' : '') . $locData['country'];
            $owner = $locData['organization'] !== 'Unknown' ? $locData['organization'] : ($locData['isp'] !== 'Unknown' ? $locData['isp'] : 'Unknown');
        }

        // 3. Store Domain-IP relationship
        $stmt = $mysqli->prepare("INSERT INTO ip_history (domain, ip, timestamp, owner, location) 
                                  VALUES (?, ?, NOW(), ?, ?) 
                                  ON DUPLICATE KEY UPDATE owner = VALUES(owner), location = VALUES(location), timestamp = NOW()");
        if ($stmt) {
            $stmt->bind_param('ssss', $domain, $ip, $owner, $location);
            $stmt->execute();
            $stmt->close();
        }

        if ($domain !== 'unknown') {
            self::storeIpDomainMapping($mysqli, $domain, $ip, 'ip_intelligence');
        }

        return true;
    }

    /**
     * Historical Tracking: Compares and saves a new DNS record snapshot if the values have changed.
     */
    public static function saveDnsSnapshot($mysqli, $domain, $recordType, $recordData) {
        if (!$mysqli || empty($domain) || empty($recordType)) return false;
        $domain = strtolower(trim($domain));
        $recordType = strtoupper(trim($recordType));
        
        $newSerialized = is_array($recordData) ? json_encode($recordData) : trim($recordData);

        // Fetch last snapshot
        $stmt = $mysqli->prepare("SELECT record_data FROM dns_snapshots WHERE domain_name = ? AND record_type = ? ORDER BY timestamp DESC LIMIT 1");
        $lastSerialized = null;
        if ($stmt) {
            $stmt->bind_param('ss', $domain, $recordType);
            $stmt->execute();
            $stmt->bind_result($lastSerialized);
            $stmt->fetch();
            $stmt->close();
        }

        // If changed or completely new, store snapshot
        if ($lastSerialized === null || $lastSerialized !== $newSerialized) {
            $stmtInsert = $mysqli->prepare("INSERT INTO dns_snapshots (domain_name, record_type, record_data) VALUES (?, ?, ?)");
            if ($stmtInsert) {
                $stmtInsert->bind_param('sss', $domain, $recordType, $newSerialized);
                $stmtInsert->execute();
                $stmtInsert->close();
                return true;
            }
        }
        return false;
    }

    /**
     * Historical Tracking: Compares and saves a WHOIS history snapshot when organization, registrar, or nameservers transition.
     */
    public static function saveWhoisSnapshot($mysqli, $domain, $summary, $raw) {
        if (!$mysqli || empty($domain) || empty($summary)) return false;
        $domain = strtolower(trim($domain));

        $registrar = $summary['Registrar'] ?? null;
        $abuseEmail = $summary['Abuse Email'] ?? null;
        $org = $summary['Organization'] ?? null;
        $nsStr = !empty($summary['Name Servers']) ? implode(',', (array)$summary['Name Servers']) : null;

        // Fetch last snapshot
        $stmt = $mysqli->prepare("SELECT registrar, organization, nameserver FROM whois_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 1");
        $lastReg = null; $lastOrg = null; $lastNs = null;
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $stmt->bind_result($lastReg, $lastOrg, $lastNs);
            $stmt->fetch();
            $stmt->close();
        }

        // If transition detected, write new snapshot
        if ($lastReg === null || $lastReg !== $registrar || $lastOrg !== $org || $lastNs !== $nsStr) {
            $stmtInsert = $mysqli->prepare("INSERT INTO whois_snapshots (domain_name, registrar, abuse_email, organization, nameserver, raw_data) VALUES (?, ?, ?, ?, ?, ?)");
            if ($stmtInsert) {
                $stmtInsert->bind_param('ssssss', $domain, $registrar, $abuseEmail, $org, $nsStr, $raw);
                $stmtInsert->execute();
                $stmtInsert->close();
                return true;
            }
        }
        return false;
    }

    /**
     * Historical Tracking: Compares and saves a new nameserver snapshot if the nameservers have changed.
     */
    public static function saveNsSnapshot($mysqli, $domain, $nsList) {
        if (!$mysqli || empty($domain) || empty($nsList)) return false;
        $domain = strtolower(trim($domain));
        
        sort($nsList);
        $newSerialized = implode(',', $nsList);

        // Fetch last snapshot
        $stmt = $mysqli->prepare("SELECT nameservers FROM ns_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 1");
        $lastSerialized = null;
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $stmt->bind_result($lastSerialized);
            $stmt->fetch();
            $stmt->close();
        }

        // If changed or completely new, store snapshot
        if ($lastSerialized === null || $lastSerialized !== $newSerialized) {
            $stmtInsert = $mysqli->prepare("INSERT INTO ns_snapshots (domain_name, nameservers) VALUES (?, ?)");
            if ($stmtInsert) {
                $stmtInsert->bind_param('ss', $domain, $newSerialized);
                $stmtInsert->execute();
                $stmtInsert->close();
                return true;
            }
        }
        return false;
    }
}