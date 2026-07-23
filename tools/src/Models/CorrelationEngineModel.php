<?php

class CorrelationEngineModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    /**
     * Generates a unique fingerprint signature for a domain based on its infrastructure.
     */
    public function getFingerprint($domain) {
        $domain = strtolower(trim($domain));
        
        $registrar = 'Unknown';
        $org = 'Unknown';
        $ns = [];
        $mx = [];
        $ips = [];

        if (!$this->mysqli) return null;

        // Fetch WHOIS attributes
        $stmt = $this->mysqli->prepare("SELECT registrar, organization, nameserver FROM whois_records WHERE domain_name = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $stmt->bind_result($dbReg, $dbOrg, $dbNs);
            if ($stmt->fetch()) {
                if (!empty($dbReg)) $registrar = $dbReg;
                if (!empty($dbOrg)) $org = $dbOrg;
                if (!empty($dbNs)) $ns = array_map('trim', explode(',', $dbNs));
            }
            $stmt->close();
        }

        // Fetch MX mapping
        $stmt = $this->mysqli->prepare("SELECT mx_server FROM mx_mapping WHERE domain = ?");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $mx[] = $row['mx_server'];
            }
            $stmt->close();
        }

        // Fetch IP history
        $stmt = $this->mysqli->prepare("SELECT DISTINCT ip FROM ip_history WHERE domain = ? LIMIT 5");
        if ($stmt) {
            $stmt->bind_param('s', $domain);
            $stmt->execute();
            $res = $stmt->get_result();
            while ($row = $res->fetch_assoc()) {
                $ips[] = $row['ip'];
            }
            $stmt->close();
        }

        sort($ns);
        sort($mx);
        sort($ips);

        $fpString = "REG:{$registrar} | ORG:{$org} | NS:" . implode(',', $ns) . " | MX:" . implode(',', $mx) . " | IPS:" . implode(',', $ips);
        
        return [
            'signature_text' => $fpString,
            'hash' => md5($fpString),
            'registrar' => $registrar,
            'organization' => $org,
            'nameservers' => $ns,
            'mx_servers' => $mx,
            'ips' => $ips
        ];
    }

    /**
     * Map similar domains sharing overlapping MX, NS, Subnets, or Registrar/Org.
     */
    public function findRelatedInfrastructure($domain) {
        $domain = strtolower(trim($domain));
        $fp = $this->getFingerprint($domain);
        if (!$fp) return [];

        $related = [];

        if (!$this->mysqli) return [];

        // 1. Domains sharing same nameservers
        if (!empty($fp['nameservers'])) {
            foreach ($fp['nameservers'] as $nsServer) {
                $stmt = $this->mysqli->prepare("SELECT DISTINCT domain FROM ns_mapping WHERE LOWER(nameserver) = ? AND domain != ? LIMIT 10");
                if ($stmt) {
                    $stmt->bind_param('ss', $nsServer, $domain);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $d = $row['domain'];
                        $related[$d]['nameservers'][] = $nsServer;
                    }
                    $stmt->close();
                }
            }
        }

        // 2. Domains sharing same MX servers
        if (!empty($fp['mx_servers'])) {
            foreach ($fp['mx_servers'] as $mxServer) {
                $stmt = $this->mysqli->prepare("SELECT DISTINCT domain FROM mx_mapping WHERE LOWER(mx_server) = ? AND domain != ? LIMIT 10");
                if ($stmt) {
                    $stmt->bind_param('ss', $mxServer, $domain);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $d = $row['domain'];
                        $related[$d]['mx_servers'][] = $mxServer;
                    }
                    $stmt->close();
                }
            }
        }

        // 3. Domains sharing same Registrar or Org
        if ($fp['registrar'] !== 'Unknown' || $fp['organization'] !== 'Unknown') {
            $stmt = $this->mysqli->prepare("SELECT domain_name, registrar, organization FROM whois_records 
                                            WHERE (LOWER(registrar) = ? OR LOWER(organization) = ?) AND domain_name != ? LIMIT 20");
            if ($stmt) {
                $regLower = strtolower($fp['registrar']);
                $orgLower = strtolower($fp['organization']);
                $stmt->bind_param('sss', $regLower, $orgLower, $domain);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $d = $row['domain_name'];
                    if (strcasecmp($row['registrar'], $fp['registrar']) === 0) {
                        $related[$d]['registrar'] = $row['registrar'];
                    }
                    if (strcasecmp($row['organization'], $fp['organization']) === 0) {
                        $related[$d]['organization'] = $row['organization'];
                    }
                }
                $stmt->close();
            }
        }

        // 4. Domains sharing same IP subnet (/24 range)
        if (!empty($fp['ips'])) {
            foreach ($fp['ips'] as $ip) {
                $parts = explode('.', $ip);
                if (count($parts) === 4) {
                    $subnetPattern = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.%';
                    $stmt = $this->mysqli->prepare("SELECT DISTINCT domain, ip FROM ip_history WHERE ip LIKE ? AND domain != ? LIMIT 10");
                    if ($stmt) {
                        $stmt->bind_param('ss', $subnetPattern, $domain);
                        $stmt->execute();
                        $res = $stmt->get_result();
                        while ($row = $res->fetch_assoc()) {
                            $d = $row['domain'];
                            $related[$d]['subnets'][] = ['ip' => $row['ip'], 'range' => $subnetPattern];
                        }
                        $stmt->close();
                    }
                }
            }
        }

        // Format and compute similarity percentage for each related domain
        $output = [];
        foreach ($related as $relDomain => $overlaps) {
            $similarity = 0;
            $reasons = [];

            if (isset($overlaps['registrar'])) {
                $similarity += 20;
                $reasons[] = "Registrar match: " . $overlaps['registrar'];
            }
            if (isset($overlaps['organization'])) {
                $similarity += 35;
                $reasons[] = "Registrant Organization match: " . $overlaps['organization'];
            }
            if (isset($overlaps['nameservers'])) {
                $count = count($overlaps['nameservers']);
                $similarity += min(20, $count * 10);
                $reasons[] = "Shared nameservers: " . implode(', ', $overlaps['nameservers']);
            }
            if (isset($overlaps['mx_servers'])) {
                $count = count($overlaps['mx_servers']);
                $similarity += min(15, $count * 8);
                $reasons[] = "Shared MX mail exchangers: " . implode(', ', $overlaps['mx_servers']);
            }
            if (isset($overlaps['subnets'])) {
                $similarity += 10;
                $reasons[] = "Subnet match (/24 neighborhood overlaps)";
            }

            $similarity = min(100, $similarity);

            $output[] = [
                'domain' => $relDomain,
                'similarity_percentage' => $similarity,
                'relationship_overlaps' => $overlaps,
                'overlap_indicators' => $reasons,
                'confidence' => $similarity >= 75 ? 'High Correlation' : ($similarity >= 40 ? 'Medium Correlation' : 'Low Correlation')
            ];
        }

        // Sort by similarity descending
        usort($output, function($a, $b) {
            return $b['similarity_percentage'] - $a['similarity_percentage'];
        });

        return $output;
    }
}
