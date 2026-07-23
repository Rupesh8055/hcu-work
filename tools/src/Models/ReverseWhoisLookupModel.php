<?php
class ReverseWhoisLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($query) {
        if (empty($query)) return ['error' => 'Search query is required.'];
        try {
            $query = strtolower(trim($query));
            $domains = $this->findDomainsFromDatabase($query);
            return [
                'query' => $query,
                'domains' => $domains,
                'total_count' => count($domains),
                'count' => count($domains),
                'timestamp' => date('Y-m-d H:i:s'),
                'source' => 'ViewDNS API & Internal DB'
            ];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while performing reverse WHOIS lookup.'];
        }
    }
    private function findDomainsFromDatabase($query) {
        $domains = [];
        
        // 1. Try ViewDNS.info scraper first as it has global coverage
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://viewdns.info/reversewhois/?q=" . urlencode($query));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36");
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $html = curl_exec($ch);
        curl_close($ch);

        if ($html) {
            if (preg_match_all('/<tr>\s*<td[^>]*>(.*?)<\/td>\s*<td[^>]*>(.*?)<\/td>\s*<td[^>]*>(.*?)<\/td>\s*<\/tr>/is', $html, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $domain = strip_tags(trim($match[1]));
                    if (!empty($domain) && strtolower($domain) !== 'domain name') {
                        $domains[] = [
                            'domain' => $domain,
                            'first_seen' => strip_tags(trim($match[2])),
                            'last_seen' => ''
                        ];
                    }
                }
            }
        }
        
        // 2. If we found results, return them
        if (count($domains) > 0) {
            return $domains;
        }
        if (!$this->mysqli || $this->mysqli->connect_errno) return $domains;
        try {
            $searchPattern = '%' . $query . '%';
            // We search entity mappings
            $sql = "SELECT domain, first_seen, last_seen FROM whois_entity_mapping WHERE entity_value LIKE ? ORDER BY last_seen DESC LIMIT 1000";
            $stmt = $this->mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param('s', $searchPattern);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc()) {
                    if (!empty($row['domain'])) {
                        $domains[] = [
                            'domain' => $row['domain'],
                            'first_seen' => $row['first_seen'] ?? '',
                            'last_seen' => $row['last_seen'] ?? ''
                        ];
                    }
                }
                $stmt->close();
            }
        } catch (Exception $e) {}
        return $domains;
    }
}