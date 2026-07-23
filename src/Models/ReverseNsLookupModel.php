<?php
class ReverseNsLookupModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function lookup($ns) {
        if (empty($ns)) return ['error' => 'Nameserver is required'];
        $ns = strtolower(trim(rtrim($ns, '.')));

        try {
            $domains = [];
            $provider = $this->identifyProvider($ns);
            $seenDomains = [];
            
            // 1. Try HackerTarget API for massive coverage
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, "https://api.hackertarget.com/findshareddns/?q=" . urlencode($ns));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            $htData = curl_exec($ch);
            curl_close($ch);
            
            if ($htData && stripos($htData, 'error') === false && stripos($htData, 'API count exceeded') === false) {
                $lines = explode("\n", trim($htData));
                foreach ($lines as $line) {
                    $domain = strtolower(trim($line));
                    if (!empty($domain) && strpos($domain, ' ') === false && !isset($seenDomains[$domain])) {
                        $domains[] = [
                            'domain' => $domain,
                            'first_seen' => 'N/A',
                            'last_seen' => date('Y-m-d H:i:s')
                        ];
                        $seenDomains[$domain] = true;
                    }
                }
            }
            
            // 2. Fetch from Internal Database
            $stmt = $this->mysqli->prepare("SELECT domain, first_seen, last_seen FROM ns_mapping WHERE LOWER(nameserver) = ? OR nameserver LIKE ? ORDER BY last_seen DESC LIMIT 500");
            if ($stmt) {
                $likeNs = '%' . $ns . '%';
                $stmt->bind_param('ss', $ns, $likeNs);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $d = strtolower(trim($row['domain']));
                    if (!isset($seenDomains[$d])) {
                        $domains[] = [
                            'domain' => $d,
                            'first_seen' => $row['first_seen'],
                            'last_seen' => $row['last_seen']
                        ];
                        $seenDomains[$d] = true;
                    }
                }
                $stmt->close();
            }

            return [
                'nameserver' => $ns,
                'provider_note' => $provider,
                'domains' => $domains,
                'count' => count($domains),
                'message' => empty($domains) ? 'No domains found in our local database for this nameserver yet. Data builds progressively as domains are scanned.' : '',
                'timestamp' => date('Y-m-d H:i:s')
            ];
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    private function identifyProvider($ns) {
        $providers = [
            'cloudflare' => 'Cloudflare DNS',
            'awsdns' => 'Amazon Route 53',
            'google' => 'Google Cloud DNS',
            'azure-dns' => 'Microsoft Azure DNS',
            'digitalocean' => 'DigitalOcean DNS',
            'linode' => 'Linode DNS',
            'namecheap' => 'Namecheap Hosting',
            'bluehost' => 'Bluehost DNS',
            'godaddy' => 'GoDaddy DNS',
            'sedoparking' => 'Sedo Domain Parking',
            'dan.com' => 'DAN Domain Parking'
        ];

        foreach ($providers as $key => $name) {
            if (stripos($ns, $key) !== false) return $name;
        }
        return 'Private / Unidentified Provider';
    }
}