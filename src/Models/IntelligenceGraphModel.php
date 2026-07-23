<?php
class IntelligenceGraphModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function buildGraph($query) {
        $query = strtolower(trim($query));
        if (empty($query)) return ['error' => 'Query is required'];

        $nodes = [];
        $edges = [];
        $nodeMap = [];

        // Helper to add nodes safely
        $addNode = function($id, $label, $group) use (&$nodes, &$nodeMap) {
            if (!isset($nodeMap[$id])) {
                $nodes[] = ['id' => $id, 'label' => $label, 'group' => $group];
                $nodeMap[$id] = true;
            }
        };

        // Helper to add edges safely
        $addEdge = function($from, $to, $label) use (&$edges) {
            $edgeId = $from . '_' . $to . '_' . $label;
            $edges[$edgeId] = ['from' => $from, 'to' => $to, 'label' => $label];
        };

        $isIp = filter_var($query, FILTER_VALIDATE_IP);
        $rootGroup = $isIp ? 'ip' : 'domain';
        $addNode($query, $query, $rootGroup);

        if (!$this->mysqli) return ['nodes' => $nodes, 'edges' => array_values($edges)];

        try {
            if (!$isIp) {
                // 1. Get IPs from ip_domain_mapping
                $stmt = $this->mysqli->prepare("SELECT ip FROM ip_domain_mapping WHERE domain = ?");
                $stmt->bind_param('s', $query);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $ip = $row['ip'];
                    $addNode($ip, $ip, 'ip');
                    $addEdge($query, $ip, 'Resolves To');
                }
                $stmt->close();

                // 2. Get WHOIS entities from whois_entity_mapping
                $stmt = $this->mysqli->prepare("SELECT entity_value, entity_type FROM whois_entity_mapping WHERE domain = ?");
                $stmt->bind_param('s', $query);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $val = $row['entity_value'];
                    $type = $row['entity_type'];
                    $addNode($val, $val, $type); // type: email, organization, registrant
                    $addEdge($query, $val, 'Registered By');
                    
                    // Look for other domains registered by this entity
                    $stmt2 = $this->mysqli->prepare("SELECT domain FROM whois_entity_mapping WHERE entity_value = ? AND domain != ? LIMIT 10");
                    $stmt2->bind_param('ss', $val, $query);
                    $stmt2->execute();
                    $res2 = $stmt2->get_result();
                    while ($row2 = $res2->fetch_assoc()) {
                        $otherDomain = $row2['domain'];
                        $addNode($otherDomain, $otherDomain, 'domain');
                        $addEdge($val, $otherDomain, 'Owns');
                    }
                    $stmt2->close();
                }
                $stmt->close();

                // 3. Get Nameservers
                $stmt = $this->mysqli->prepare("SELECT nameserver FROM ns_mapping WHERE domain = ? LIMIT 10");
                if ($stmt) {
                    $stmt->bind_param('s', $query);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $ns = $row['nameserver'];
                        $addNode($ns, $ns, 'nameserver');
                        $addEdge($query, $ns, 'Uses NS');
                    }
                    $stmt->close();
                }
            } else {
                // Query is an IP
                // Get domains mapped to this IP
                $stmt = $this->mysqli->prepare("SELECT domain FROM ip_domain_mapping WHERE ip = ? LIMIT 50");
                $stmt->bind_param('s', $query);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $domain = $row['domain'];
                    $addNode($domain, $domain, 'domain');
                    $addEdge($query, $domain, 'Hosts');
                }
                $stmt->close();
            }
        } catch (\Exception $e) {}

        return [
            'nodes' => $nodes,
            'edges' => array_values($edges)
        ];
    }
}
