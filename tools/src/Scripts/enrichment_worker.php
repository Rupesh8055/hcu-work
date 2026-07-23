<?php
require_once __DIR__ . '/../../db_system.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Models/IpHistoryModel.php';

echo "Background Infrastructure Enrichment Worker Started.\n";

$ipHistoryModel = new IpHistoryModel($mysqli);

while (true) {
    // Pick 50 random domains to enrich
    $stmt = $mysqli->query("SELECT DISTINCT domain FROM ip_domain_mapping WHERE domain != 'unknown' AND domain != 'localhost' ORDER BY RAND() LIMIT 50");
    
    $domains = [];
    if ($stmt) {
        while ($row = $stmt->fetch_assoc()) {
            $domains[] = $row['domain'];
        }
    }
    
    if (empty($domains)) {
        echo "No domains found. Sleeping...\n";
        sleep(10);
        continue;
    }
    
    foreach ($domains as $domain) {
        // Resolve DNS A, AAAA, NS, MX
        $records = @dns_get_record($domain, DNS_A | DNS_AAAA | DNS_NS | DNS_MX);
        if ($records && is_array($records)) {
            DatabaseManager::accumulateDnsIntelligence($mysqli, $domain, $records);
            
            // Log A and AAAA into IpHistory
            foreach ($records as $record) {
                if ($record['type'] === 'A' || $record['type'] === 'AAAA') {
                    $ip = $record['ip'] ?? $record['ipv6'] ?? null;
                    if ($ip) {
                        $ipHistoryModel->saveEntry($domain, $ip, 'enrichment_worker');
                    }
                }
            }
        }
        
        // Also do a reverse lookup on the IP if available (legacy IPv4)
        $ip = gethostbyname($domain);
        if ($ip !== $domain) {
            DatabaseManager::storeIpDomainMapping($mysqli, $domain, $ip, 'enrichment_worker', 80);
            DatabaseManager::accumulateIpIntelligence($mysqli, $ip);
            $ipHistoryModel->saveEntry($domain, $ip, 'enrichment_worker');
        }
        
        usleep(200000); // 200ms
    }
    
    sleep(5);
}
