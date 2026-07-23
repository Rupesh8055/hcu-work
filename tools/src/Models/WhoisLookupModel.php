<?php
class WhoisLookupModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function lookup($domain) {
        if (empty($domain)) {
            return ['error' => 'Domain/IP parameter is required.'];
        }
        
        $domain = strtolower(trim($domain));
        if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) && !filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['error' => 'Invalid domain or IP format provided.'];
        }

        try {
            // 1. Try checking database cache first
            $cachedData = $this->lookupFromDatabase($domain);
            if (!empty($cachedData)) {
                $cachedData['history'] = $this->getWhoisHistory($domain);
                return $cachedData;
            }

            // 2. Perform live TCP/UDP socket WHOIS lookup
            $rawWhois = $this->whoisTcpChained($domain);
            if ($rawWhois && !$this->isErrorResponse($rawWhois)) {
                $summary = $this->parseWhoisSummary($rawWhois);
                
                // Store nameservers for Reverse NS dataset building
                if (!empty($summary['Name Servers']) && is_array($summary['Name Servers'])) {
                    require_once __DIR__ . '/../Includes/DatabaseManager.php';
                    DatabaseManager::storeNameservers($this->mysqli, $domain, $summary['Name Servers']);
                    foreach ($summary['Name Servers'] as $ns) {
                        if (filter_var($ns, FILTER_VALIDATE_IP)) {
                            DatabaseManager::storeIpDomainMapping($this->mysqli, $domain, $ns, 'whois_ns', 60);
                        } else {
                            $ip = @gethostbyname($ns);
                            if ($ip && $ip !== $ns && filter_var($ip, FILTER_VALIDATE_IP)) {
                                DatabaseManager::storeIpDomainMapping($this->mysqli, $domain, $ip, 'whois_ns', 60);
                                DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
                            }
                        }
                    }
                }
                
                // Store domain to IP mapping if possible
                if (!filter_var($domain, FILTER_VALIDATE_IP)) {
                    $ip = @gethostbyname($domain);
                    if ($ip && $ip !== $domain && filter_var($ip, FILTER_VALIDATE_IP)) {
                        require_once __DIR__ . '/../Includes/DatabaseManager.php';
                        DatabaseManager::storeIpDomainMapping($this->mysqli, $domain, $ip, 'whois_domain', 70);
                        DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);
                    }
                }

                // Standardize and normalize
                if (isset($summary['Creation Date'])) {
                    $summary['Creation Date'] = $this->normalizeWhoisDate($summary['Creation Date']);
                }
                if (isset($summary['Expiration Date'])) {
                    $summary['Expiration Date'] = $this->normalizeWhoisDate($summary['Expiration Date']);
                }

                // Save to the persistent whois_records table
                $this->saveToDatabase($domain, $summary, $rawWhois);

                // Save WHOIS snapshot for historical transition tracking
                require_once __DIR__ . '/../Includes/DatabaseManager.php';
                DatabaseManager::saveWhoisSnapshot($this->mysqli, $domain, $summary, $rawWhois);

                return [
                    'domain' => $domain,
                    'raw' => $rawWhois,
                    'formatted' => $rawWhois,
                    'summary' => $summary,
                    'details' => $this->parseWhoisDetails($rawWhois),
                    'history' => $this->getWhoisHistory($domain),
                    'source' => 'live_whois'
                ];
            }

            return ['error' => 'Could not retrieve WHOIS data. Outgoing Port 43 might be blocked on this server, or TLD is not supported.'];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while looking up WHOIS information: ' . $e->getMessage()];
        }
    }

    private function whoisTcpChained($q) {
        $server = 'whois.iana.org';
        $first = $this->whoisTcpOnce($server, $q);
        if ($first && !$this->isErrorResponse($first)) {
            if (preg_match('/refer:\s*(.+)/i', $first, $m) || preg_match('/whois:\s*(.+)/i', $first, $m)) {
                $ref = trim($m[1]);
                if ($ref !== $server) {
                    $second = $this->whoisTcpOnce($ref, $q);
                    if ($second && !$this->isErrorResponse($second)) {
                        return $second;
                    }
                }
            }
            return $first;
        }

        // Fallback for IPs if IANA fails
        if (filter_var($q, FILTER_VALIDATE_IP)) {
            $servers = ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net', 'whois.lacnic.net', 'whois.afrinic.net'];
            foreach ($servers as $s) {
                $res = $this->whoisTcpOnce($s, $q);
                if ($res && !$this->isErrorResponse($res)) return $res;
            }
        } else {
            // TLD Specific Fallback
            $tldServers = $this->getTldWhoisServers($q);
            foreach ($tldServers as $s) {
                $res = $this->whoisTcpOnce($s, $q);
                if ($res && !$this->isErrorResponse($res)) return $res;
            }
        }
        return null;
    }

    private function getTldWhoisServers($domain) {
        $parts = explode('.', $domain);
        $tld = end($parts);
        $tldServers = [
            'com' => 'whois.verisign-grs.com', 'net' => 'whois.verisign-grs.com', 'org' => 'whois.pir.org',
            'edu' => 'whois.educause.edu', 'gov' => 'whois.nic.gov', 'uk' => 'whois.nic.uk',
            'de' => 'whois.denic.de', 'fr' => 'whois.afnic.fr', 'jp' => 'whois.jprs.jp',
            'au' => 'whois.aunic.net', 'ca' => 'whois.cira.ca', 'cn' => 'whois.cnnic.net.cn',
            'in' => 'whois.inregistry.net', 'br' => 'whois.registro.br', 'ru' => 'whois.tcinet.ru',
            'it' => 'whois.nic.it', 'es' => 'whois.nic.es', 'nl' => 'whois.domain-registry.nl',
            'se' => 'whois.iis.se', 'no' => 'whois.norid.no', 'dk' => 'whois.dk-hostmaster.dk',
            'fi' => 'whois.fi', 'pl' => 'whois.dns.pl', 'ie' => 'whois.iedr.ie',
            'nz' => 'whois.srs.net.nz', 'za' => 'whois.registry.net.za', 'mx' => 'whois.mx',
            'ar' => 'whois.nic.ar', 'co' => 'whois.nic.co', 'io' => 'whois.nic.io',
            'ai' => 'whois.nic.ai', 'tv' => 'whois.tv', 'me' => 'whois.nic.me',
            'info' => 'whois.afilias.net', 'biz' => 'whois.nic.biz', 'name' => 'whois.nic.name',
            'mobi' => 'whois.afilias.net', 'asia' => 'whois.nic.asia', 'tel' => 'whois.nic.tel',
            'pro' => 'whois.registrypro.pro', 'travel' => 'whois.nic.travel', 'xxx' => 'whois.nic.xxx',
            'jobs' => 'whois.nic.jobs', 'museum' => 'whois.museum', 'aero' => 'whois.information.aero',
            'coop' => 'whois.nic.coop', 'int' => 'whois.iana.org'
        ];
        return isset($tldServers[$tld]) ? [$tldServers[$tld]] : [];
    }

    private function isErrorResponse($response) {
        if (empty($response)) return true;
        $errorPatterns = ['not found', 'no entries found', 'no match', 'no data found', 'no whois server', 'error', 'timeout', 'connection refused', 'connection timed out'];
        $responseLower = strtolower($response);
        foreach ($errorPatterns as $pattern) {
            if (strpos($responseLower, $pattern) !== false) return true;
        }
        return false;
    }

    private function whoisTcpOnce($server, $q) {
        // Strip trailing dot or protocol
        $server = strtolower(trim($server));
        $fp = @fsockopen($server, 43, $errno, $errstr, 5);
        if (!$fp) return null;
        stream_set_timeout($fp, 5);
        
        // Handle specific ARIN query format if IP searched
        if ($server === 'whois.arin.net' && filter_var($q, FILTER_VALIDATE_IP)) {
            fwrite($fp, "n + " . $q . "\r\n");
        } else {
            fwrite($fp, $q . "\r\n");
        }

        $out = '';
        $startTime = time();
        while (!feof($fp) && (time() - $startTime) < 8) {
            $line = fgets($fp, 1024);
            if ($line === false) break;
            $out .= $line;
        }
        fclose($fp);
        return trim($out) ?: null;
    }

    private function normalizeWhoisDate($dateStr) {
        if (empty($dateStr)) return null;
        $dateStr = trim($dateStr);
        // Strips timezone names or millisecond trails
        $clean = preg_replace('/(\d{4}-\d{2}-\d{2})[T\s].*/', '$1', $dateStr);
        $time = strtotime($clean);
        if ($time === false) {
            $time = strtotime($dateStr);
        }
        return $time ? date('Y-m-d', $time) : $dateStr;
    }

    private function parseWhoisSummary($raw) {
        $s = [
            'Registrar' => 'Unknown',
            'Creation Date' => 'Unknown',
            'Expiration Date' => 'Unknown',
            'Organization' => 'Unknown',
            'Abuse Email' => 'Unknown',
            'Name Servers' => [],
            'Domain Status' => [],
            'Registrant' => 'Unknown',
            'Admin Email' => 'Unknown',
            'Network' => 'Unknown'
        ];

        // Normalization Regex Matchers
        if (preg_match('/Registrar:\s*(.+)/i', $raw, $m) || preg_match('/Registrar Name:\s*(.+)/i', $raw, $m)) $s['Registrar'] = trim($m[1]);
        if (preg_match('/Creation Date:\s*(.+)/i', $raw, $m) || preg_match('/Registered on:\s*(.+)/i', $raw, $m) || preg_match('/created:\s*(.+)/i', $raw, $m)) $s['Creation Date'] = trim($m[1]);
        if (preg_match('/Registry Expiry Date:\s*(.+)/i', $raw, $m) || preg_match('/Expiry Date:\s*(.+)/i', $raw, $m) || preg_match('/Expiration Date:\s*(.+)/i', $raw, $m) || preg_match('/paid-till:\s*(.+)/i', $raw, $m)) $s['Expiration Date'] = trim($m[1]);
        if (preg_match('/Registrant Organization:\s*(.+)/i', $raw, $m) || preg_match('/OrgName:\s*(.+)/i', $raw, $m)) $s['Organization'] = trim($m[1]);
        if (preg_match('/Registrar Abuse Contact Email:\s*(.+)/i', $raw, $m) || preg_match('/abuse-email:\s*(.+)/i', $raw, $m) || preg_match('/Abuse Contact:\s*(.+)/i', $raw, $m)) $s['Abuse Email'] = trim($m[1]);
        if (preg_match('/Registrant Name:\s*(.+)/i', $raw, $m) || preg_match('/registrant:\s*(.+)/i', $raw, $m)) $s['Registrant'] = trim($m[1]);
        if (preg_match('/Admin Email:\s*(.+)/i', $raw, $m)) $s['Admin Email'] = trim($m[1]);
        if (preg_match('/NetName:\s*(.+)/i', $raw, $m) || preg_match('/Network Name:\s*(.+)/i', $raw, $m)) $s['Network'] = trim($m[1]);

        // Fallback for Abuse Email Extraction
        if ($s['Abuse Email'] === 'Unknown') {
            $emailPattern = '/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/i';
            if (preg_match_all($emailPattern, $raw, $matches)) {
                foreach ($matches[1] as $email) {
                    $emailLower = strtolower($email);
                    if (strpos($emailLower, 'abuse') !== false || strpos($emailLower, 'noc') !== false) {
                        $s['Abuse Email'] = $email;
                        break;
                    }
                }
                if ($s['Abuse Email'] === 'Unknown' && !empty($matches[1])) {
                    $s['Abuse Email'] = $matches[1][0];
                }
            }
        }

        // Nameserver Extraction and Normalization
        preg_match_all('/Name Server:\s*([^\s]+)/i', $raw, $nsMatches);
        if (empty($nsMatches[1])) preg_match_all('/nserver:\s*([^\s]+)/i', $raw, $nsMatches);
        if (!empty($nsMatches[1])) {
            $nsList = array_map('trim', $nsMatches[1]);
            $nsList = array_map(function($ns) { return strtolower(rtrim($ns, '.')); }, $nsList);
            $s['Name Servers'] = array_values(array_unique(array_filter($nsList)));
        }

        // Domain Status Extraction
        preg_match_all('/Domain Status:\s*([a-zA-Z]+)/i', $raw, $statusMatches);
        if (!empty($statusMatches[1])) {
            $s['Domain Status'] = array_values(array_unique(array_map('trim', $statusMatches[1])));
        }

        return $s;
    }

    private function parseWhoisDetails($raw) {
        $lines = preg_split('/\r?\n/', $raw);
        $details = [];
        foreach ($lines as $line) {
            if (strpos($line, ':') === false) continue;
            list($k, $v) = explode(':', $line, 2);
            $k = trim($k); $v = trim($v);
            if ($k === '' || $v === '' || strlen($k) > 100) continue;
            if (!isset($details[$k])) $details[$k] = $v;
        }
        return $details;
    }

    private function lookupFromDatabase($domain) {
        if (!$this->mysqli) return null;
        try {
            $stmt = $this->mysqli->prepare("SELECT * FROM whois_records WHERE domain_name = ?");
            if ($stmt) {
                $stmt->bind_param('s', $domain);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($result && $result->num_rows > 0) {
                    $row = $result->fetch_assoc();
                    $stmt->close();
                    return [
                        'domain' => $domain,
                        'raw' => $row['raw_data'] ?? '',
                        'formatted' => $row['raw_data'] ?? '',
                        'summary' => [
                            'Registrar' => $row['registrar'] ?? 'Unknown',
                            'Creation Date' => $row['creation_date'] ?? 'Unknown',
                            'Expiration Date' => $row['expiration_date'] ?? 'Unknown',
                            'Organization' => $row['organization'] ?? 'Unknown',
                            'Abuse Email' => $row['abuse_email'] ?? 'Unknown',
                            'Name Servers' => !empty($row['nameserver']) ? explode(',', $row['nameserver']) : [],
                            'Registrant' => $row['registrant'] ?? 'Unknown',
                            'Admin Email' => $row['admin_email'] ?? 'Unknown',
                            'Network' => $row['network'] ?? 'Unknown'
                        ],
                        'details' => $this->parseWhoisDetails($row['raw_data'] ?? ''),
                        'source' => 'local_database'
                    ];
                }
                $stmt->close();
            }
        } catch (Exception $e) {}
        return null;
    }

    private function saveToDatabase($domain, $summary, $raw) {
        if (!$this->mysqli) return false;
        try {
            $isIp = filter_var($domain, FILTER_VALIDATE_IP);
            $ipAddress = $isIp ? $domain : null;
            
            $registrar = $summary['Registrar'] ?? null;
            $abuseEmail = $summary['Abuse Email'] ?? null;
            $org = $summary['Organization'] ?? null;
            $network = $summary['Network'] ?? null;
            $created = $summary['Creation Date'] ?? null;
            $expired = $summary['Expiration Date'] ?? null;
            $registrant = $summary['Registrant'] ?? null;
            $adminEmail = $summary['Admin Email'] ?? null;
            
            $nsStr = !empty($summary['Name Servers']) ? implode(',', (array)$summary['Name Servers']) : null;

            $sql = "INSERT INTO whois_records (domain_name, ip_address, registrar, abuse_email, organization, network, raw_data, creation_date, expiration_date, nameserver, registrant, admin_email) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                    ON DUPLICATE KEY UPDATE 
                    ip_address = VALUES(ip_address), registrar = VALUES(registrar), abuse_email = VALUES(abuse_email), 
                    organization = VALUES(organization), network = VALUES(network), raw_data = VALUES(raw_data), 
                    creation_date = VALUES(creation_date), expiration_date = VALUES(expiration_date), 
                    nameserver = VALUES(nameserver), registrant = VALUES(registrant), admin_email = VALUES(admin_email)";
            
            $stmt = $this->mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param('ssssssssssss', $domain, $ipAddress, $registrar, $abuseEmail, $org, $network, $raw, $created, $expired, $nsStr, $registrant, $adminEmail);
                $stmt->execute();
                $stmt->close();
                
                // Populate whois_entity_mapping
                $this->storeWhoisEntityMapping($domain, 'email', $abuseEmail);
                $this->storeWhoisEntityMapping($domain, 'email', $adminEmail);
                $this->storeWhoisEntityMapping($domain, 'organization', $org);
                $this->storeWhoisEntityMapping($domain, 'registrant', $registrant);
                
                return true;
            }
        } catch (Exception $e) {}
        return false;
    }

    private function storeWhoisEntityMapping($domain, $type, $value) {
        if (empty($value) || $value === 'Unknown' || strtolower($value) === 'redacted for privacy' || strtolower($value) === 'privacy service provided by withheld for privacy ehf') return;
        $value = strtolower(trim($value));
        $domain = strtolower(trim($domain));
        
        $sql = "INSERT INTO whois_entity_mapping (entity_value, entity_type, domain, first_seen, last_seen) 
                VALUES (?, ?, ?, NOW(), NOW()) 
                ON DUPLICATE KEY UPDATE last_seen = NOW()";
        $stmt = $this->mysqli->prepare($sql);
        if ($stmt) {
            $stmt->bind_param('sss', $value, $type, $domain);
            $stmt->execute();
            $stmt->close();
        }
    }

    private function getWhoisHistory($domain) {
        $history = [];
        if (!$this->mysqli) return $history;
        $stmt = $this->mysqli->prepare("SELECT registrar, organization, nameserver, timestamp FROM whois_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 20");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $history[] = [
                    'registrar' => $row['registrar'] ?? 'Unknown',
                    'organization' => $row['organization'] ?? 'Unknown',
                    'nameservers' => !empty($row['nameserver']) ? explode(',', $row['nameserver']) : [],
                    'timestamp' => $row['timestamp']
                ];
            }
            $stmt->close();
        }
        return $history;
    }
}