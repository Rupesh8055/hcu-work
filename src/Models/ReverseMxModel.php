<?php
class ReverseMxModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($mx) {
        if (empty($mx)) return ['error' => 'MX host is required.'];
        try {
            ini_set('memory_limit', '1048M');
            set_time_limit(600);
            $lookupPatterns = [$mx];
            if (filter_var($mx, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                $mxRecords = @dns_get_record($mx, DNS_MX);
                if ($mxRecords) {
                    foreach ($mxRecords as $record) {
                        if (!empty($record['target'])) {
                            $target = strtolower(rtrim($record['target'], '.'));
                            $lookupPatterns[] = $target;
                            $parts = explode('.', $target);
                            if (count($parts) >= 2) $lookupPatterns[] = implode('.', array_slice($parts, -2));
                        }
                    }
                }
            }
            $lookupPatterns = array_unique($lookupPatterns);
            $domains = $this->findDomainsFromDatabase($lookupPatterns);
            return [
                'mx' => $mx,
                'resolved_patterns' => $lookupPatterns,
                'domains' => $domains,
                'count' => count($domains),
                'timestamp' => date('Y-m-d H:i:s'),
                'source' => !empty($domains) ? 'internal_database' : 'no_records_found'
            ];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while fetching reverse MX results.'];
        }
    }
    private function findDomainsFromDatabase($lookupPatterns) {
        $domains = [];
        if (!$this->mysqli || $this->mysqli->connect_errno) return $domains;
        try {
            $queryParts = []; $params = []; $types = "";
            foreach ($lookupPatterns as $pattern) {
                $queryParts[] = "mx_record LIKE ?";
                $params[] = '%' . strtolower(rtrim($pattern, '.')) . '%';
                $types .= "s";
            }
            if (empty($queryParts)) return $domains;
            
            // Query domains_mx without arbitrary small limits to ensure all results are returned
            $sql = "SELECT domain, mx_record FROM domains_mx WHERE " . implode(" OR ", $queryParts);
            $stmt = $this->mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param($types, ...$params);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc()) {
                    if (!empty($row['domain'])) {
                        $domains[] = [
                            'domain' => strtolower(trim($row['domain'])),
                            'priority' => 10,
                            'last_seen' => date('Y-m-d H:i:s')
                        ];
                    }
                }
                $stmt->close();
            }
        } catch (Exception $e) {}
        
        // Remove duplicates while keeping the most recent
        $uniqueDomains = [];
        foreach ($domains as $d) {
            $domainName = $d['domain'];
            if (!isset($uniqueDomains[$domainName])) {
                $uniqueDomains[$domainName] = $d;
            }
        }
        return array_values($uniqueDomains);
    }
}