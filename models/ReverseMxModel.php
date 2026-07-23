<?php
class ReverseMxModel {
    private $mysqli;
    private $cache = [];
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    
    public function getDomainsByMx($mxHosts) {
        if (empty($mxHosts)) return [];
        
        $cache_key = md5(serialize($mxHosts));
        if (isset($this->cache[$cache_key])) {
            return $this->cache[$cache_key];
        }
        
        $conditions = [];
        $params = [];
        foreach ($mxHosts as $mx) {
            $conditions[] = "mx_record LIKE ?";
            $params[] = "%$mx%";
        }
        
        $sql = "SELECT domain FROM domains_mx WHERE " . implode(" OR ", $conditions) . " ORDER BY domain";
        $stmt = $this->mysqli->prepare($sql);
        $types = str_repeat('s', count($params));
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $result = $stmt->get_result();
        $domains = [];
        while ($row = $result->fetch_assoc()) {
            $domains[] = $row['domain'];
        }
        $stmt->close();
        
        $this->cache[$cache_key] = $domains;
        return $domains;
    }
    
    public function addDomain($domain, $mx_record) {
        $sql = "INSERT INTO domains_mx (domain, mx_record) VALUES (?, ?) ON DUPLICATE KEY UPDATE mx_record = ?";
        $stmt = $this->mysqli->prepare($sql);
        $stmt->bind_param('sss', $domain, $mx_record, $mx_record);
        return $stmt->execute();
    }
    
    public function updateDomain($domain, $mx_record) {
        $sql = "UPDATE domains_mx SET mx_record = ? WHERE domain = ?";
        $stmt = $this->mysqli->prepare($sql);
        $stmt->bind_param('ss', $mx_record, $domain);
        return $stmt->execute();
    }
    
    public function deleteDomain($domain) {
        $sql = "DELETE FROM domains_mx WHERE domain = ?";
        $stmt = $this->mysqli->prepare($sql);
        $stmt->bind_param('s', $domain);
        return $stmt->execute();
    }
}
?>
