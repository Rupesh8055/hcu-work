<?php
require_once __DIR__ . '/CorrelationEngineModel.php';

class IntelligenceSearchModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function search($query) {
        if (empty($query)) return ['error' => 'Search term is required.'];
        $query = strtolower(trim($query));
        $likePattern = '%' . $query . '%';

        try {
            $nodes = [
                'domains' => [],
                'ips' => [],
                'nameservers' => [],
                'registrars' => [],
                'organizations' => [],
                'mx_servers' => [],
                'relationships' => []
            ];

            // 1. Search whois_records for domains, registrars, organizations, nameservers
            $sqlWhois = "SELECT domain_name, ip_address, registrar, organization, nameserver 
                         FROM whois_records 
                         WHERE domain_name LIKE ? OR registrar LIKE ? OR organization LIKE ? OR nameserver LIKE ? 
                         LIMIT 100";
            $stmt = $this->mysqli->prepare($sqlWhois);
            if ($stmt) {
                $stmt->bind_param('ssss', $likePattern, $likePattern, $likePattern, $likePattern);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $nodes['domains'][] = [
                        'name' => $row['domain_name'],
                        'ip' => $row['ip_address'] ?? 'Unknown',
                        'registrar' => $row['registrar'] ?? 'Unknown',
                        'organization' => $row['organization'] ?? 'Unknown'
                    ];
                    if (!empty($row['registrar'])) $nodes['registrars'][] = $row['registrar'];
                    if (!empty($row['organization'])) $nodes['organizations'][] = $row['organization'];
                    if (!empty($row['nameserver'])) {
                        foreach (explode(',', $row['nameserver']) as $ns) {
                            $nodes['nameservers'][] = trim($ns);
                        }
                    }
                }
                $stmt->close();
            }

            // 2. Search ip_history for IP & ASN associations
            $sqlIp = "SELECT domain, ip, owner, location 
                      FROM ip_history 
                      WHERE ip LIKE ? OR domain LIKE ? OR owner LIKE ? 
                      LIMIT 100";
            $stmt = $this->mysqli->prepare($sqlIp);
            if ($stmt) {
                $stmt->bind_param('sss', $likePattern, $likePattern, $likePattern);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $nodes['ips'][] = [
                        'ip' => $row['ip'],
                        'domain' => $row['domain'],
                        'owner' => $row['owner'] ?? 'Unknown',
                        'location' => $row['location'] ?? 'Unknown'
                    ];
                    if (!empty($row['owner'])) $nodes['organizations'][] = $row['owner'];
                }
                $stmt->close();
            }

            // 3. Search ns_mapping for nameserver connections
            $sqlNs = "SELECT nameserver, domain FROM ns_mapping WHERE nameserver LIKE ? OR domain LIKE ? LIMIT 100";
            $stmt = $this->mysqli->prepare($sqlNs);
            if ($stmt) {
                $stmt->bind_param('ss', $likePattern, $likePattern);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $nodes['nameservers'][] = $row['nameserver'];
                    $nodes['domains'][] = [
                        'name' => $row['domain'],
                        'registrar' => 'Unknown',
                        'organization' => 'Unknown',
                        'ip' => 'Unknown'
                    ];
                }
                $stmt->close();
            }

            // 4. Search mx_mapping for MX exchanger overlaps
            $sqlMx = "SELECT domain, mx_server FROM mx_mapping WHERE mx_server LIKE ? OR domain LIKE ? LIMIT 100";
            $stmt = $this->mysqli->prepare($sqlMx);
            if ($stmt) {
                $stmt->bind_param('ss', $likePattern, $likePattern);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $nodes['mx_servers'][] = $row['mx_server'];
                    $nodes['domains'][] = [
                        'name' => $row['domain'],
                        'registrar' => 'Unknown',
                        'organization' => 'Unknown',
                        'ip' => 'Unknown'
                    ];
                }
                $stmt->close();
            }

            // Deduplicate lists
            $nodes['registrars'] = array_values(array_unique($nodes['registrars']));
            $nodes['organizations'] = array_values(array_unique($nodes['organizations']));
            $nodes['nameservers'] = array_values(array_unique($nodes['nameservers']));
            $nodes['mx_servers'] = array_values(array_unique($nodes['mx_servers']));
            
            $uniqueDomains = [];
            $tempDomains = [];
            foreach ($nodes['domains'] as $d) {
                $name = strtolower(trim($d['name']));
                if (!in_array($name, $tempDomains) && !empty($name)) {
                    $tempDomains[] = $name;
                    $uniqueDomains[] = [
                        'name' => $name,
                        'ip' => $d['ip'] ?? 'Unknown',
                        'registrar' => $d['registrar'] ?? 'Unknown',
                        'organization' => $d['organization'] ?? 'Unknown'
                    ];
                }
            }
            $nodes['domains'] = $uniqueDomains;

            // 5. Build Deep Infrastructure Overlaps & Relationship Tree via CorrelationEngineModel
            $correlationEngine = new CorrelationEngineModel($this->mysqli);
            $domainLimits = array_slice($nodes['domains'], 0, 5); // limit computation to top 5 domains to prevent timeouts
            foreach ($domainLimits as $d) {
                $relations = $correlationEngine->findRelatedInfrastructure($d['name']);
                foreach ($relations as $rel) {
                    if ($rel['similarity_percentage'] >= 25) {
                        $nodes['relationships'][] = [
                            'source' => $d['name'],
                            'target' => $rel['domain'],
                            'similarity' => $rel['similarity_percentage'],
                            'confidence' => $rel['confidence'],
                            'indicators' => $rel['overlap_indicators']
                        ];
                    }
                }
            }

            return [
                'query' => $query,
                'nodes' => [
                    'domains_count' => count($nodes['domains']),
                    'ips_count' => count($nodes['ips']),
                    'nameservers_count' => count($nodes['nameservers']),
                    'registrars_count' => count($nodes['registrars']),
                    'organizations_count' => count($nodes['organizations']),
                    'mx_servers_count' => count($nodes['mx_servers']),
                    'relationships_count' => count($nodes['relationships']),
                    'details' => $nodes
                ],
                'timestamp' => date('c')
            ];

        } catch (Exception $e) {
            return ['error' => 'An error occurred during multi-node search: ' . $e->getMessage()];
        }
    }
}
