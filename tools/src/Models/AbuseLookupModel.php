<?php
class AbuseLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($query) {
        @set_time_limit(120);
        if (empty($query)) return ['error' => 'Query parameter required.'];
        if (!filter_var($query, FILTER_VALIDATE_IP) && !filter_var($query, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return ['error' => 'Invalid input.'];
        try {
            $results = $this->lookupFromDatabase($query);
            if (empty($results)) $results = $this->performLiveWhoisLookup($query);
            if (empty($results)) return ['error' => 'No information available.'];
            return $results;
        } catch (Exception $e) {
            return ['error' => 'An error occurred during lookup.'];
        }
    }
    private function performLiveWhoisLookup($query) {
        $rawWhois = $this->whoisTcpChained($query);
        if (!$rawWhois || empty(trim($rawWhois))) return null;
        $parsed = $this->parseWhoisForAbuse($rawWhois, $query);
        if ($parsed && (!empty($parsed['whois_abuse']) || !empty($parsed['organization']))) {
            $this->saveToDatabase($query, $parsed, $rawWhois);
            return $parsed;
        }
        return null;
    }
    private function whoisTcpChained($q) {
        $isIp = filter_var($q, FILTER_VALIDATE_IP);
        if ($isIp) {
            $servers = $this->determineRirServers($q);
            foreach ($servers as $server) {
                $result = $this->whoisTcpOnce($server, $q);
                if ($result && !$this->isErrorResponse($result)) return $result;
            }
        } else {
            $server = 'whois.iana.org';
            $first = $this->whoisTcpOnce($server, $q);
            if ($first && !$this->isErrorResponse($first)) {
                if (preg_match('/refer:\s*(.+)/i', $first, $m)) {
                    $ref = trim($m[1]);
                    $second = $this->whoisTcpOnce($ref, $q);
                    if ($second && !$this->isErrorResponse($second)) return $second;
                }
                return $first;
            }
            $tldServers = $this->getTldWhoisServers($q);
            foreach ($tldServers as $server) {
                $result = $this->whoisTcpOnce($server, $q);
                if ($result && !$this->isErrorResponse($result)) return $result;
            }
        }
        return null;
    }
    private function determineRirServers($ip) {
        $servers = [];
        $ipLong = ip2long($ip);
        if ($ipLong === false) return ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net'];
        if (($ipLong >= 0 && $ipLong <= 16777215) || ($ipLong >= 2147483648 && $ipLong <= 3355443199)) $servers[] = 'whois.arin.net';
        if (($ipLong >= 1037959168 && $ipLong <= 1040187391) || ($ipLong >= 1342177280 && $ipLong <= 1610612735)) $servers[] = 'whois.ripe.net';
        if (($ipLong >= 16777216 && $ipLong <= 1037959167) || ($ipLong >= 1728053248 && $ipLong <= 1744830463)) $servers[] = 'whois.apnic.net';
        if (($ipLong >= 2969567232 && $ipLong <= 2971666431) || ($ipLong >= 3003121664 && $ipLong <= 3005220863)) $servers[] = 'whois.lacnic.net';
        if (($ipLong >= 687865856 && $ipLong <= 704643071) || ($ipLong >= 1711276032 && $ipLong <= 1728053247)) $servers[] = 'whois.afrinic.net';
        if (empty($servers)) $servers = ['whois.arin.net', 'whois.ripe.net', 'whois.apnic.net'];
        else {
            if (!in_array('whois.arin.net', $servers)) $servers[] = 'whois.arin.net';
            if (!in_array('whois.ripe.net', $servers)) $servers[] = 'whois.ripe.net';
        }
        return $servers;
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
        $errorPatterns = ['not found', 'no entries found', 'no match', 'no data found', 'no whois server', 'error', 'timeout'];
        $responseLower = strtolower($response);
        foreach ($errorPatterns as $pattern) if (strpos($responseLower, $pattern) !== false) return true;
        return false;
    }
    private function whoisTcpOnce($server, $q) {
        $fp = @fsockopen($server, 43, $errno, $errstr, 10);
        if (!$fp) return null;
        stream_set_timeout($fp, 12);
        fwrite($fp, $q . "\r\n");
        $out = '';
        $startTime = time();
        while (!feof($fp) && (time() - $startTime) < 12) {
            $line = fgets($fp, 1024);
            if ($line === false) break;
            $out .= $line;
        }
        fclose($fp);
        return trim($out) ?: null;
    }
    private function parseWhoisForAbuse($rawWhois, $query) {
        $result = [
            'query' => $query, 'registrar' => null, 'whois_abuse' => null, 'organization' => null,
            'network' => null, 'full_record' => $rawWhois, 'source' => 'live_whois'
        ];
        $lines = preg_split('/\r?\n/', $rawWhois);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            
            if (preg_match('/^(?:Registrar|Sponsoring Registrar):\s*(.+)$/i', $line, $m) && !$result['registrar']) $result['registrar'] = trim($m[1]);
            if (preg_match('/^(?:OrgName|Organization|org|Registrant Organization):\s*(.+)$/i', $line, $m) && !$result['organization']) $result['organization'] = trim($m[1]);
            if (preg_match('/^(?:NetName|Network Name):\s*(.+)$/i', $line, $m) && !$result['network']) $result['network'] = trim($m[1]);
            
            // Comprehensive Abuse Email checks
            if (preg_match('/^(?:Registrar\s+)?Abuse\s+(?:Contact\s+)?Email:\s*(.+)$/i', $line, $m) && !$result['whois_abuse']) $result['whois_abuse'] = trim($m[1]);
            if (preg_match('/^OrgAbuseEmail:\s*(.+)$/i', $line, $m) && !$result['whois_abuse']) $result['whois_abuse'] = trim($m[1]);
            if (preg_match('/^abuse-mailbox:\s*(.+)$/i', $line, $m) && !$result['whois_abuse']) $result['whois_abuse'] = trim($m[1]);
            if (preg_match('/^abuse[\-\s]?email:\s*(.+)$/i', $line, $m) && !$result['whois_abuse']) $result['whois_abuse'] = trim($m[1]);
            if (preg_match('/^abuse-c:\s*(.+)$/i', $line, $m) && !$result['whois_abuse'] && filter_var(trim($m[1]), FILTER_VALIDATE_EMAIL)) $result['whois_abuse'] = trim($m[1]);
        }
        if (empty($result['whois_abuse'])) {
            $emailPattern = '/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/i';
            if (preg_match_all($emailPattern, $rawWhois, $matches)) {
                foreach ($matches[1] as $email) {
                    $emailLower = strtolower($email);
                    if (strpos($emailLower, 'abuse') !== false || strpos($emailLower, 'noc') !== false || strpos($emailLower, 'security') !== false) {
                        $result['whois_abuse'] = $email;
                        break;
                    }
                }
                if (empty($result['whois_abuse']) && !empty($matches[1])) {
                    // Filter out common non-abuse emails like whois@ or nic@
                    foreach ($matches[1] as $email) {
                        $emailLower = strtolower($email);
                        if (strpos($emailLower, 'whois') === false && strpos($emailLower, 'nic@') === false) {
                            $result['whois_abuse'] = $email;
                            break;
                        }
                    }
                    if (empty($result['whois_abuse'])) $result['whois_abuse'] = $matches[1][0];
                }
            }
        }
        return $result;
    }
    private function saveToDatabase($query, $parsed, $rawWhois) {
        if (!$this->mysqli || $this->mysqli->connect_errno) return false;
        try {
            $stmt = $this->mysqli->prepare("INSERT INTO whois_records (domain_name, ip_address, registrar, abuse_email, organization, network, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE registrar = VALUES(registrar), abuse_email = VALUES(abuse_email), organization = VALUES(organization), network = VALUES(network), raw_data = VALUES(raw_data)");
            if ($stmt) {
                $isIp = filter_var($query, FILTER_VALIDATE_IP);
                $ipAddress = $isIp ? $query : null;
                $stmt->bind_param('sssssss', $query, $ipAddress, $parsed['registrar'], $parsed['whois_abuse'], $parsed['organization'], $parsed['network'], $rawWhois);
                $stmt->execute();
                $stmt->close();
            }
        } catch (Exception $e) {}
    }
    private function lookupFromDatabase($query) {
        if (!$this->mysqli || $this->mysqli->connect_errno) return null;
        try {
            $stmt = $this->mysqli->prepare("SELECT * FROM whois_records WHERE domain_name = ? OR ip_address = ?");
            if ($stmt) {
                $stmt->bind_param('ss', $query, $query);
                $stmt->execute();
                $res = $stmt->get_result();
                if ($res && $res->num_rows > 0) {
                    $row = $res->fetch_assoc();
                    $stmt->close();
                    return [
                        'query' => $query, 'registrar' => $row['registrar'], 'whois_abuse' => $row['abuse_email'],
                        'organization' => $row['organization'], 'network' => $row['network'],
                        'full_record' => $row['raw_data'], 'source' => 'local_database'
                    ];
                }
                $stmt->close();
            }
        } catch (Exception $e) {}
        return null;
    }
}