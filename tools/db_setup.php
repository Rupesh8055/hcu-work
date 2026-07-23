<?php
require_once __DIR__ . '/db_system.php';

if (!$mysqli) {
    die("Database connection failed.\n");
}

$queries = [
    // Drop old overlapping tables
    "DROP TABLE IF EXISTS domain_ip_history",
    "DROP TABLE IF EXISTS domain_nameservers",
    "DROP TABLE IF EXISTS tool_cache",
    "DROP TABLE IF EXISTS lookup_logs",
    "DROP TABLE IF EXISTS tool_results",
    "DROP TABLE IF EXISTS ip_history",
    "DROP TABLE IF EXISTS ns_mapping",
    "DROP TABLE IF EXISTS whois_records",
    "DROP TABLE IF EXISTS dns_snapshots",
    "DROP TABLE IF EXISTS whois_snapshots",
    "DROP TABLE IF EXISTS rate_limits",
    "DROP TABLE IF EXISTS mx_mapping",
    "DROP TABLE IF EXISTS ns_snapshots",
    "DROP TABLE IF EXISTS ip_ranges",
    "DROP TABLE IF EXISTS scan_queue",
    "DROP TABLE IF EXISTS background_jobs",
    "DROP TABLE IF EXISTS blocked_ips",
    "DROP TABLE IF EXISTS ip_blocks",
    "DROP TABLE IF EXISTS security_logs",

    // Create lookup_logs
    "CREATE TABLE IF NOT EXISTS lookup_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_ip VARCHAR(45) NOT NULL,
        tool_name VARCHAR(100) NOT NULL,
        input_query VARCHAR(1000) NOT NULL,
        error_message VARCHAR(500),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_logs_tool_input (tool_name(64), input_query(255)),
        INDEX idx_logs_created (created_at)
    )",

    // Create tool_results
    "CREATE TABLE IF NOT EXISTS tool_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tool_name VARCHAR(100) NOT NULL,
        input_query VARCHAR(1000) NOT NULL,
        result_data JSON,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        status ENUM('fresh', 'expired', 'refreshing') DEFAULT 'fresh',
        UNIQUE KEY uq_tool_input (tool_name(64), input_query(255)),
        INDEX idx_results_status (status)
    )",

    // Create ip_history
    "CREATE TABLE IF NOT EXISTS ip_history (
        domain VARCHAR(255) NOT NULL,
        ip VARCHAR(45) NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        owner VARCHAR(255) DEFAULT 'Unknown',
        location VARCHAR(255) DEFAULT 'Unknown',
        PRIMARY KEY (domain, ip, timestamp),
        INDEX idx_ip_history_ip (ip),
        INDEX idx_ip_history_domain (domain(64)),
        INDEX idx_ip_history_timestamp (timestamp)
    )",

    // Create ns_mapping
    "CREATE TABLE IF NOT EXISTS ns_mapping (
        domain VARCHAR(255) NOT NULL,
        nameserver VARCHAR(255) NOT NULL,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (domain, nameserver),
        INDEX idx_ns_mapping_domain (domain(64)),
        INDEX idx_ns_mapping_ns (nameserver(64))
    )",

    // Create whois_records
    "CREATE TABLE IF NOT EXISTS whois_records (
        domain_name VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45) NULL,
        registrar VARCHAR(255) NULL,
        abuse_email VARCHAR(255) NULL,
        organization VARCHAR(255) NULL,
        network VARCHAR(255) NULL,
        raw_data MEDIUMTEXT NULL,
        creation_date VARCHAR(100) NULL,
        expiration_date VARCHAR(100) NULL,
        nameserver TEXT NULL,
        registrant VARCHAR(255) NULL,
        admin_email VARCHAR(255) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (domain_name),
        INDEX idx_whois_ip (ip_address),
        INDEX idx_whois_org (organization(64)),
        INDEX idx_whois_registrar (registrar(64))
    )",

    // Create dns_snapshots
    "CREATE TABLE IF NOT EXISTS dns_snapshots (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain_name VARCHAR(255) NOT NULL,
        record_type VARCHAR(10) NOT NULL,
        record_data TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_dns_snap_domain (domain_name(64)),
        INDEX idx_dns_snap_time (timestamp)
    ) ENGINE=InnoDB",

    // Create whois_snapshots
    "CREATE TABLE IF NOT EXISTS whois_snapshots (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain_name VARCHAR(255) NOT NULL,
        registrar VARCHAR(255) NULL,
        abuse_email VARCHAR(255) NULL,
        organization VARCHAR(255) NULL,
        nameserver TEXT NULL,
        raw_data MEDIUMTEXT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_whois_snap_domain (domain_name(64)),
        INDEX idx_whois_snap_time (timestamp)
    ) ENGINE=InnoDB",

    // Create rate_limits
    "CREATE TABLE IF NOT EXISTS rate_limits (
        ip_address VARCHAR(45) NOT NULL,
        tool VARCHAR(100) NOT NULL,
        request_count INT NOT NULL DEFAULT 1,
        window_start DATETIME NOT NULL,
        PRIMARY KEY (ip_address, tool),
        INDEX idx_limits_window (window_start)
    ) ENGINE=InnoDB",

    // Create mx_mapping
    "CREATE TABLE IF NOT EXISTS mx_mapping (
        domain VARCHAR(255) NOT NULL,
        mx_server VARCHAR(255) NOT NULL,
        priority INT DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (domain, mx_server),
        INDEX idx_mx_mapping_server (mx_server(64))
    ) ENGINE=InnoDB",

    // Create ns_snapshots
    "CREATE TABLE IF NOT EXISTS ns_snapshots (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain_name VARCHAR(255) NOT NULL,
        nameservers TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ns_snap_domain (domain_name(64)),
        INDEX idx_ns_snap_time (timestamp)
    ) ENGINE=InnoDB",

    // Create ip_ranges
    "CREATE TABLE IF NOT EXISTS ip_ranges (
        id INT AUTO_INCREMENT PRIMARY KEY,
        start_ip_num INT UNSIGNED NOT NULL,
        end_ip_num INT UNSIGNED NOT NULL,
        cidr VARCHAR(45) NOT NULL,
        country_code VARCHAR(2) NOT NULL,
        asn INT NULL,
        isp_org VARCHAR(255) NOT NULL,
        registry VARCHAR(20) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_ip_range (start_ip_num, end_ip_num),
        INDEX idx_range_lookup (start_ip_num, end_ip_num)
    ) ENGINE=InnoDB",

    // Create scan_queue
    "CREATE TABLE IF NOT EXISTS scan_queue (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tool_name VARCHAR(100) NOT NULL,
        input_query VARCHAR(1000) NOT NULL,
        priority INT DEFAULT 0,
        status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
        error_message TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        started_at DATETIME NULL,
        completed_at DATETIME NULL,
        INDEX idx_queue_lookup (status, priority, created_at)
    ) ENGINE=InnoDB",

    // Create background_jobs
    "CREATE TABLE IF NOT EXISTS background_jobs (
        id VARCHAR(64) PRIMARY KEY,
        job_type VARCHAR(100) NOT NULL,
        target_data TEXT NOT NULL,
        priority INT DEFAULT 0,
        status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
        result_data JSON NULL,
        error_message TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_jobs_status (status, priority, created_at)
    ) ENGINE=InnoDB",

    // Create ip_domain_mapping
    "CREATE TABLE IF NOT EXISTS ip_domain_mapping (
        domain varchar(255) NOT NULL,
        ip varchar(45) NOT NULL,
        first_seen datetime DEFAULT current_timestamp(),
        source_tool varchar(50) DEFAULT 'unknown',
        last_seen datetime DEFAULT current_timestamp(),
        confidence int(11) DEFAULT 50,
        observation_count int(11) DEFAULT 1,
        PRIMARY KEY (domain,ip),
        KEY idx_ip_domain_ip (ip),
        KEY idx_ip_domain_domain (domain)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // Create free_email_domains
    "CREATE TABLE IF NOT EXISTS free_email_domains (
        id int(11) NOT NULL AUTO_INCREMENT,
        domain varchar(255) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY domain_unique (domain)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci",

    // Create vendors
    "CREATE TABLE IF NOT EXISTS vendors (
        id int(6) unsigned NOT NULL AUTO_INCREMENT,
        macPrefix varchar(18) NOT NULL,
        vendorName varchar(255) NOT NULL,
        private tinyint(1) DEFAULT NULL,
        blockType varchar(10) DEFAULT NULL,
        lastUpdate varchar(20) DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci",

    // Create whois_entity_mapping
    "CREATE TABLE IF NOT EXISTS whois_entity_mapping (
        entity_value varchar(255) NOT NULL,
        entity_type enum('email','organization','registrant') NOT NULL,
        domain varchar(255) NOT NULL,
        first_seen datetime DEFAULT current_timestamp(),
        last_seen datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
        PRIMARY KEY (entity_value,entity_type,domain),
        KEY idx_whois_entity_val (entity_value(64)),
        KEY idx_whois_entity_domain (domain(64))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // Create circuit_breakers
    "CREATE TABLE IF NOT EXISTS circuit_breakers (
        service_name varchar(64) NOT NULL,
        failures int(11) DEFAULT 0,
        state enum('closed','open','half_open') DEFAULT 'closed',
        last_failure timestamp NULL DEFAULT NULL,
        PRIMARY KEY (service_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

    // Create domains_mx
    "CREATE TABLE IF NOT EXISTS domains_mx (
        id int(11) NOT NULL AUTO_INCREMENT,
        domain text DEFAULT NULL,
        mx_record text DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci"
];

foreach ($queries as $query) {
    if ($mysqli->query($query) === TRUE) {
        echo "Query executed successfully.\n";
    } else {
        echo "Error: " . $mysqli->error . "\n";
    }
}

// Seed the ip_ranges database table for high out-of-the-box accuracy
$rirSeeds = [
    ['start' => '1.0.0.0', 'end' => '1.255.255.255', 'cc' => 'AU', 'asn' => 13335, 'org' => 'APNIC / Cloudflare DNS', 'reg' => 'APNIC'],
    ['start' => '2.0.0.0', 'end' => '2.255.255.255', 'cc' => 'FR', 'asn' => 3215, 'org' => 'RIPE NCC / Orange', 'reg' => 'RIPE'],
    ['start' => '3.0.0.0', 'end' => '3.255.255.255', 'cc' => 'US', 'asn' => 16509, 'org' => 'Amazon.com, Inc. / AWS', 'reg' => 'ARIN'],
    ['start' => '4.0.0.0', 'end' => '4.255.255.255', 'cc' => 'US', 'asn' => 3356, 'org' => 'Level 3 Communications', 'reg' => 'ARIN'],
    ['start' => '5.0.0.0', 'end' => '5.255.255.255', 'cc' => 'DE', 'asn' => 31334, 'org' => 'RIPE NCC / Vodafone DE', 'reg' => 'RIPE'],
    ['start' => '8.0.0.0', 'end' => '8.255.255.255', 'cc' => 'US', 'asn' => 15169, 'org' => 'Google LLC / Public DNS', 'reg' => 'ARIN'],
    ['start' => '9.0.0.0', 'end' => '9.255.255.255', 'cc' => 'US', 'asn' => 19281, 'org' => 'IBM Corporation / Quad9', 'reg' => 'ARIN'],
    ['start' => '13.0.0.0', 'end' => '13.255.255.255', 'cc' => 'US', 'asn' => 8075, 'org' => 'Microsoft Corporation', 'reg' => 'ARIN'],
    ['start' => '17.0.0.0', 'end' => '17.255.255.255', 'cc' => 'US', 'asn' => 714, 'org' => 'Apple Computer Inc.', 'reg' => 'ARIN'],
    ['start' => '18.0.0.0', 'end' => '18.255.255.255', 'cc' => 'US', 'asn' => 3, 'org' => 'Massachusetts Institute of Technology', 'reg' => 'ARIN'],
    ['start' => '23.0.0.0', 'end' => '23.255.255.255', 'cc' => 'US', 'asn' => 20940, 'org' => 'Akamai Technologies', 'reg' => 'ARIN'],
    ['start' => '31.0.0.0', 'end' => '31.255.255.255', 'cc' => 'GB', 'asn' => 12513, 'org' => 'RIPE NCC / Sky UK', 'reg' => 'RIPE'],
    ['start' => '34.0.0.0', 'end' => '34.255.255.255', 'cc' => 'US', 'asn' => 15169, 'org' => 'Google LLC / GCP', 'reg' => 'ARIN'],
    ['start' => '35.0.0.0', 'end' => '35.255.255.255', 'cc' => 'US', 'asn' => 16509, 'org' => 'Amazon.com, Inc. / AWS', 'reg' => 'ARIN'],
    ['start' => '41.0.0.0', 'end' => '41.255.255.255', 'cc' => 'ZA', 'asn' => 37153, 'org' => 'AFRINIC / Liquid Telecom', 'reg' => 'AFRINIC'],
    ['start' => '45.0.0.0', 'end' => '45.255.255.255', 'cc' => 'US', 'asn' => 14356, 'org' => 'ARIN Block Allocation', 'reg' => 'ARIN'],
    ['start' => '46.0.0.0', 'end' => '46.255.255.255', 'cc' => 'RU', 'asn' => 3223, 'org' => 'RIPE NCC / Rostelecom', 'reg' => 'RIPE'],
    ['start' => '52.0.0.0', 'end' => '52.255.255.255', 'cc' => 'US', 'asn' => 16509, 'org' => 'Amazon.com, Inc. / AWS', 'reg' => 'ARIN'],
    ['start' => '104.0.0.0', 'end' => '104.255.255.255', 'cc' => 'US', 'asn' => 13335, 'org' => 'Cloudflare / ARIN Block', 'reg' => 'ARIN'],
    ['start' => '142.250.0.0', 'end' => '142.250.255.255', 'cc' => 'US', 'asn' => 15169, 'org' => 'Google LLC Services', 'reg' => 'ARIN'],
    ['start' => '172.217.0.0', 'end' => '172.217.255.255', 'cc' => 'US', 'asn' => 15169, 'org' => 'Google LLC Services', 'reg' => 'ARIN'],
    ['start' => '185.0.0.0', 'end' => '185.255.255.255', 'cc' => 'CH', 'asn' => 62240, 'org' => 'RIPE NCC / ProtonVPN', 'reg' => 'RIPE'],
    ['start' => '192.0.0.0', 'end' => '192.255.255.255', 'cc' => 'US', 'asn' => 701, 'org' => 'Verizon Business', 'reg' => 'ARIN'],
    ['start' => '200.0.0.0', 'end' => '200.255.255.255', 'cc' => 'BR', 'asn' => 27699, 'org' => 'LACNIC / Telemar BR', 'reg' => 'LACNIC'],
    ['start' => '210.0.0.0', 'end' => '210.255.255.255', 'cc' => 'IN', 'asn' => 55836, 'org' => 'Reliance Jio Infocomm', 'reg' => 'APNIC']
];

$stmt = $mysqli->prepare("INSERT INTO ip_ranges (start_ip_num, end_ip_num, cidr, country_code, asn, isp_org, registry) VALUES (?, ?, ?, ?, ?, ?, ?)");
if ($stmt) {
    foreach ($rirSeeds as $seed) {
        $startNum = sprintf('%u', ip2long($seed['start']));
        $endNum = sprintf('%u', ip2long($seed['end']));
        $cidr = $seed['start'] . '/8';
        if (strpos($seed['start'], '142.') === 0 || strpos($seed['start'], '172.') === 0) {
            $cidr = $seed['start'] . '/16';
        }
        
        $stmt->bind_param('iississ', $startNum, $endNum, $cidr, $seed['cc'], $seed['asn'], $seed['org'], $seed['reg']);
        $stmt->execute();
    }
    $stmt->close();
    echo "IP Ranges successfully seeded!\n";
} else {
    echo "Failed to prepare seed statement: " . $mysqli->error . "\n";
}

echo "Database setup completed.\n";
