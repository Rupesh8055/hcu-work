<?php
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class DnsReportModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function getReport($domain) {
        if (empty($domain)) return ['error' => 'Domain is required'];
        $domain = strtolower(trim($domain));

        $startTime = microtime(true);
        
        $results = [
            'A' => $this->checkRecord($domain, DNS_A),
            'AAAA' => $this->checkRecord($domain, DNS_AAAA),
            'MX' => $this->checkRecord($domain, DNS_MX),
            'NS' => $this->checkRecord($domain, DNS_NS),
            'TXT' => $this->checkRecord($domain, DNS_TXT),
            'SOA' => $this->checkRecord($domain, DNS_SOA),
        ];

        // Store nameservers and accumulate progressive DNS intelligence
        $allRecords = [];
        foreach ($results as $type => $recordSet) {
            if (!empty($recordSet['records'])) {
                foreach ($recordSet['records'] as $r) {
                    $allRecords[] = $r;
                }
            }
        }
        DatabaseManager::accumulateDnsIntelligence($this->mysqli, $domain, $allRecords);

        // Save nameserver snapshots specifically
        $nsList = [];
        if (!empty($results['NS']['records'])) {
            foreach ($results['NS']['records'] as $r) {
                $target = $r['target'] ?? ($r['data'] ?? '');
                if (!empty($target)) {
                    $nsList[] = strtolower(trim(rtrim($target, '.')));
                }
            }
        }
        if (!empty($nsList)) {
            DatabaseManager::saveNsSnapshot($this->mysqli, $domain, $nsList);
        }

        // Save DNS snapshots for historical timeline transitions
        foreach ($results as $type => $recordSet) {
            DatabaseManager::saveDnsSnapshot($this->mysqli, $domain, $type, $recordSet['records']);
        }

        $report = $this->runHealthTests($domain, $results);
        $advancedAnalysis = $this->runAdvancedDnsAnalysis($domain, $results);
        
        // Evaluate trust score and threat/reputation indicators
        require_once __DIR__ . '/ReputationRiskModel.php';
        $riskModel = new ReputationRiskModel($this->mysqli);
        $reputation = $riskModel->evaluate($domain);

        // Fetch historical DNS snapshot timeline for this domain
        $history = [
            'dns' => [],
            'nameservers' => []
        ];
        $stmt = $this->mysqli->prepare("SELECT record_type, record_data, timestamp FROM dns_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 15");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $history['dns'][] = [
                    'type' => $row['record_type'],
                    'data' => json_decode($row['record_data'], true) ?? $row['record_data'],
                    'timestamp' => $row['timestamp']
                ];
            }
            $stmt->close();
        }

        // Fetch nameserver snapshots
        $stmt = $this->mysqli->prepare("SELECT nameservers, timestamp FROM ns_snapshots WHERE domain_name = ? ORDER BY timestamp DESC LIMIT 15");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $history['nameservers'][] = [
                    'nameservers' => explode(',', $row['nameservers']),
                    'timestamp' => $row['timestamp']
                ];
            }
            $stmt->close();
        }

        return [
            'domain' => $domain,
            'records' => $results,
            'report' => $report,
            'security_analysis' => $advancedAnalysis,
            'reputation' => $reputation,
            'history' => $history,
            'execution_time' => round((microtime(true) - $startTime) * 1000, 2) . 'ms',
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    private function checkRecord($domain, $type) {
        $start = microtime(true);
        $records = @dns_get_record($domain, $type);
        $time = round((microtime(true) - $start) * 1000, 2);
        
        return [
            'status' => !empty($records) ? 'OK' : 'MISSING',
            'count' => is_array($records) ? count($records) : 0,
            'records' => $records ?: [],
            'response_time' => $time . 'ms'
        ];
    }

    private function runHealthTests($domain, $results) {
        $report = [
            'parent_tests' => [],
            'local_tests' => [],
            'soa_tests' => [],
            'mx_tests' => [],
            'www_tests' => []
        ];

        // 1. Parent/NS Tests
        if ($results['NS']['status'] === 'MISSING') {
            $report['parent_tests'][] = ['status' => 'FAIL', 'case' => 'Nameserver Check', 'info' => 'No NS records found. Your domain will not resolve.'];
        } else {
            $report['parent_tests'][] = ['status' => 'PASS', 'case' => 'Nameserver Check', 'info' => count($results['NS']['records']) . ' nameservers found.'];
            if (count($results['NS']['records']) < 2) {
                $report['local_tests'][] = ['status' => 'WARN', 'case' => 'NS Redundancy', 'info' => 'Only one nameserver found. Minimum 2 recommended for reliability.'];
            }
        }

        // 2. SOA Tests
        if ($results['SOA']['status'] === 'MISSING') {
            $report['soa_tests'][] = ['status' => 'FAIL', 'case' => 'SOA Check', 'info' => 'Missing SOA record. Domain is technically invalid.'];
        } else {
            $soa = $results['SOA']['records'][0];
            $report['soa_tests'][] = ['status' => 'PASS', 'case' => 'SOA Check', 'info' => 'SOA record present (Primary: ' . ($soa['mname'] ?? 'Unknown') . ')'];
            if (isset($soa['expire']) && $soa['expire'] < 604800) {
                $report['soa_tests'][] = ['status' => 'WARN', 'case' => 'SOA Expire', 'info' => 'Expire value is low (' . $soa['expire'] . '). Recommended: 1 week+.'];
            }
        }

        // 3. MX Tests
        if ($results['MX']['status'] === 'MISSING') {
            $report['mx_tests'][] = ['status' => 'INFO', 'case' => 'Mail Server Check', 'info' => 'No MX records. This domain cannot receive emails.'];
        } else {
            $report['mx_tests'][] = ['status' => 'PASS', 'case' => 'Mail Server Check', 'info' => count($results['MX']['records']) . ' mail servers configured.'];
        }

        // 4. WWW Tests
        $www = 'www.' . $domain;
        $wwwA = @dns_get_record($www, DNS_A);
        if (empty($wwwA)) {
            $report['www_tests'][] = ['status' => 'WARN', 'case' => 'WWW Check', 'info' => 'www.' . $domain . ' does not resolve. Some users might find this confusing.'];
        } else {
            $report['www_tests'][] = ['status' => 'PASS', 'case' => 'WWW Check', 'info' => 'www subdomain is correctly configured.'];
        }

        return $report;
    }

    private function runAdvancedDnsAnalysis($domain, $results) {
        $analysis = [
            'dangling_cnames' => [],
            'parked_domains' => false,
            'cdn_fingerprints' => [],
            'suspicious_ttls' => [],
            'wildcard_dns' => false,
            'mail_misconfigs' => [],
            'security_spf_dmarc' => []
        ];

        // 1. Dangling CNAMEs (Subdomain Takeover check)
        $knownEndpoints = [
            's3.amazonaws.com' => 'Amazon S3',
            'github.io' => 'GitHub Pages',
            'herokuapp.com' => 'Heroku',
            'myshopify.com' => 'Shopify',
            'azurewebsites.net' => 'Azure Web App',
            'wpengine.com' => 'WP Engine',
            'bitbucket.org' => 'Bitbucket Pages'
        ];

        $cnames = @dns_get_record($domain, DNS_CNAME);
        if (is_array($cnames)) {
            foreach ($cnames as $c) {
                if (isset($c['target'])) {
                    $target = strtolower($c['target']);
                    foreach ($knownEndpoints as $pattern => $provider) {
                        if (strpos($target, $pattern) !== false) {
                            $resolved = @gethostbyname($target);
                            if ($resolved === $target || empty($resolved)) {
                                $analysis['dangling_cnames'][] = [
                                    'subdomain' => $c['host'] ?? $domain,
                                    'target' => $c['target'],
                                    'provider' => $provider,
                                    'risk' => 'High - Potential Subdomain Takeover Vulnerability (CNAME destination does not resolve)'
                                ];
                            }
                        }
                    }
                }
            }
        }

        // 2. Parked Domain Detections (GoDaddy, Sedo, Namecheap)
        $parkingIps = [
            '34.102.136.180' => 'GoDaddy Parking',
            '184.168.131.241' => 'GoDaddy Parking',
            '92.242.140.21' => 'Barefruit Parking',
            '199.59.243.220' => 'Sedo Parking',
            '66.96.162.92' => 'Domain.com Parking',
            '192.64.119.254' => 'Namecheap Parking'
        ];
        if (!empty($results['A']['records'])) {
            foreach ($results['A']['records'] as $r) {
                $ipVal = $r['ip'] ?? ($r['data'] ?? '');
                if (filter_var($ipVal, FILTER_VALIDATE_IP) && isset($parkingIps[$ipVal])) {
                    $analysis['parked_domains'] = $parkingIps[$ipVal];
                }
            }
        }

        // 3. CDN Fingerprinting
        $cdnPatterns = [
            'cloudflare' => 'Cloudflare CDN',
            'cloudfront' => 'AWS CloudFront',
            'fastly' => 'Fastly CDN',
            'akamai' => 'Akamai CDN',
            'sucuri' => 'Sucuri WAF/CDN',
            'netdna' => 'MaxCDN'
        ];
        if (is_array($cnames)) {
            foreach ($cnames as $c) {
                if (isset($c['target'])) {
                    $target = strtolower($c['target']);
                    foreach ($cdnPatterns as $pattern => $cdnName) {
                        if (strpos($target, $pattern) !== false) {
                            $analysis['cdn_fingerprints'][] = $cdnName;
                        }
                    }
                }
            }
        }
        if (!empty($results['A']['records'])) {
            foreach ($results['A']['records'] as $r) {
                $ipVal = $r['ip'] ?? ($r['data'] ?? '');
                if (filter_var($ipVal, FILTER_VALIDATE_IP)) {
                    $ptr = @gethostbyaddr($ipVal);
                    if ($ptr) {
                        foreach ($cdnPatterns as $pattern => $cdnName) {
                            if (strpos(strtolower($ptr), $pattern) !== false) {
                                $analysis['cdn_fingerprints'][] = $cdnName;
                            }
                        }
                    }
                }
            }
        }
        $analysis['cdn_fingerprints'] = array_values(array_unique($analysis['cdn_fingerprints']));

        // 4. Suspicious TTL patterns
        foreach ($results as $type => $recordSet) {
            if (!empty($recordSet['records'])) {
                foreach ($recordSet['records'] as $r) {
                    if (isset($r['ttl']) && $r['ttl'] < 60) {
                        $analysis['suspicious_ttls'][] = "Short TTL for {$type} record ({$r['ttl']} seconds). High dynamic swapping frequency.";
                    }
                }
            }
        }

        // 5. Wildcard DNS Check
        $randSub = 'dns-health-' . rand(1000, 9999) . '.' . $domain;
        $randRes = @dns_get_record($randSub, DNS_A);
        if (!empty($randRes)) {
            $analysis['wildcard_dns'] = true;
        }

        // 6. Mail Misconfigurations
        if (!empty($results['MX']['records'])) {
            foreach ($results['MX']['records'] as $r) {
                $mxTarget = $r['target'] ?? '';
                if (empty($mxTarget) && isset($r['data'])) {
                    $parts = explode(' ', $r['data']);
                    $mxTarget = end($parts);
                }
                if (!empty($mxTarget) && filter_var($mxTarget, FILTER_VALIDATE_IP)) {
                    $analysis['mail_misconfigs'][] = "MX record points directly to IP address ({$mxTarget}). Points to IP instead of FQDN hostname.";
                }
            }
        }

        // 7. Security SPF / DMARC weaknesses
        $txts = $results['TXT']['records'];
        $spfFound = false;
        if (is_array($txts)) {
            foreach ($txts as $t) {
                $txtVal = $t['txt'] ?? ($t['data'] ?? '');
                if (stripos($txtVal, 'v=spf1') !== false) {
                    $spfFound = true;
                    if (stripos($txtVal, '+all') !== false) {
                        $analysis['security_spf_dmarc'][] = "SPF record contains insecure '+all' directive authorizing any sender IP.";
                    }
                }
            }
        }
        if (!$spfFound) {
            $analysis['security_spf_dmarc'][] = "Missing SPF (Sender Policy Framework) record.";
        }

        $dmarc = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
        if (empty($dmarc)) {
            $analysis['security_spf_dmarc'][] = "Missing DMARC policy record.";
        } else {
            $dmarcVal = $dmarc[0]['txt'] ?? ($dmarc[0]['entries'][0] ?? ($dmarc[0]['data'] ?? ''));
            if (stripos($dmarcVal, 'p=none') !== false) {
                $analysis['security_spf_dmarc'][] = "DMARC policy is set to monitoring 'p=none' (insecure).";
            }
        }

        return $analysis;
    }
}