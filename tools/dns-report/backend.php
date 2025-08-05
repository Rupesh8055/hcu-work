<?php

// Production-ready error handling
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/mnt/LocalDisk/CyberJagrithiTools/dns-report/logs/php_errors.log'); // Ensure this path is writable

// Set a custom error handler
set_error_handler(function($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        // This error code is not included in error_reporting
        return;
    }
    // Log the error
    error_log(sprintf("Error [%s]: %s in %s on line %d", $severity, $message, $file, $line));
    // Don't execute PHP internal error handler
    return true;
});

function generate_dns_report($domain) {

    if (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return ['error' => 'A valid domain name was not provided.'];
    }

    $report = [
        'parent_tests' => [],
        'local_tests' => [],
        'soa_tests' => [],
        'mx_tests' => [],
        'www_tests' => [],
    ];

    // --- Helper Functions ---
    function is_public_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // --- Helper function to find the authoritative domain for NS records ---
    function get_authoritative_ns_domain($domain) {
        $domain_parts = explode('.', $domain);
        while (count($domain_parts) > 1) {
            $current_domain = implode('.', $domain_parts);
            // Check for NS records on the current domain part
            if (@dns_get_record($current_domain, DNS_NS)) {
                return $current_domain;
            }
            // Move up to the parent domain
            array_shift($domain_parts);
        }
        return false; // Or return the original domain as a fallback
    }

    // --- 1. Parent Nameserver Tests (Approximation) ---
    $auth_domain = get_authoritative_ns_domain($domain);
    if (!$auth_domain) {
        // If we couldn't find an authoritative domain, fallback to the original domain for the query
        $auth_domain = $domain;
    }

    $parent_ns_records = @dns_get_record($auth_domain, DNS_NS);
    if ($parent_ns_records) {
        $info = [];
        foreach ($parent_ns_records as $record) {
            $ip = gethostbyname($record['target']);
            $info[] = "{$record['target']}. [{$ip}] [TTL={$record['ttl']}]";
        }
        $report['parent_tests'][] = ['status' => 'INFO', 'case' => 'NS records listed at parent servers', 'info' => implode("\n", $info)];
        $report['parent_tests'][] = ['status' => 'OK', 'case' => 'Domain listed at parent servers', 'info' => 'Good! The parent servers have information about your domain.'];
    } else {
        $report['parent_tests'][] = ['status' => 'FAIL', 'case' => 'NS records listed at parent servers', 'info' => 'Could not retrieve NS records for the domain.'];
        return $report; // Stop if no NS records
    }

    // --- 2. Local Nameserver Tests ---
    $local_ns_records = $parent_ns_records;
    $info = [];
    $local_ips = [];
    foreach ($local_ns_records as $record) {
        $ip = gethostbyname($record['target']);
        $local_ips[] = $ip;
        $info[] = "{$record['target']}. [{$ip}] [TTL={$record['ttl']}]";
    }
    $report['local_tests'][] = ['status' => 'INFO', 'case' => 'NS records at your local servers', 'info' => implode("\n", $info)];

    if (count($local_ns_records) >= 2) {
        $report['local_tests'][] = ['status' => 'OK', 'case' => 'Number of nameservers', 'info' => 'Good! You have at least 2 nameservers.'];
    } else {
        $report['local_tests'][] = ['status' => 'WARNING', 'case' => 'Number of nameservers', 'info' => 'Warning! You should have at least 2 nameservers.'];
    }

    $subnets = [];
    foreach ($local_ips as $ip) { $subnets[] = substr($ip, 0, strrpos($ip, '.')); }
    if (count(array_unique($subnets)) > 1 || count($subnets) <= 1) {
        $report['local_tests'][] = ['status' => 'OK', 'case' => 'Nameservers are on different IP subnets', 'info' => 'Good! All your nameservers are in separate class C (/24) subnets.'];
    } else {
        $report['local_tests'][] = ['status' => 'WARNING', 'case' => 'Nameservers are on different IP subnets', 'info' => 'Warning! Some or all of your nameservers are in the same class C (/24) subnet.'];
    }

    $all_public = true;
    foreach ($local_ips as $ip) { if (!is_public_ip($ip)) { $all_public = false; break; } }
    if ($all_public) {
        $report['local_tests'][] = ['status' => 'OK', 'case' => 'Nameservers have public IPs', 'info' => 'Good! All your NS records have public IP addresses.'];
    } else {
        $report['local_tests'][] = ['status' => 'FAIL', 'case' => 'Nameservers have public IPs', 'info' => 'Error! At least one of your nameservers has a private IP address.'];
    }
    
    

    // --- 3. Start of Authority (SOA) Tests ---
    $soa_record = @dns_get_record($domain, DNS_SOA);
    if ($soa_record) {
        $soa = $soa_record[0];
        $soa_info = [
            "Primary nameserver: {$soa['mname']}",
            "Hostmaster E-mail address: {$soa['rname']}",
            "Serial number: {$soa['serial']}",
            "Refresh: {$soa['refresh']}",
            "Retry: {$soa['retry']}",
            "Expire: {$soa['expire']}",
            "Minimum TTL: {$soa['ttl']}"
        ];
        $report['soa_tests'][] = ['status' => 'INFO', 'case' => 'SOA Record', 'info' => implode("\n", $soa_info)];

        if (!preg_match('/^\d{10}$/', $soa['serial']) || substr($soa['serial'], 0, 4) < 1990) {
             $report['soa_tests'][] = ['status' => 'WARNING', 'case' => 'SOA serial number format', 'info' => "Oops! Your SOA serial number ({$soa['serial']}) does not seem to be in the recommended format (YYYYMMDDnn)."];
        } else {
             $report['soa_tests'][] = ['status' => 'OK', 'case' => 'SOA serial number format', 'info' => 'Good! Your SOA serial number is in the recommended format.' ];
        }
        
        if ($soa['refresh'] >= 3600 && $soa['refresh'] <= 86400) {
            $report['soa_tests'][] = ['status' => 'OK', 'case' => 'SOA Refresh value', 'info' => 'Good! Your SOA Refresh value is within the recommended range (1-24 hours).'];
        } else {
            $report['soa_tests'][] = ['status' => 'WARNING', 'case' => 'SOA Refresh value', 'info' => 'Oops! Your SOA Refresh value is outside the recommended range (1-24 hours).'];
        }

        if ($soa['retry'] >= 300 && $soa['retry'] <= 14400) {
            $report['soa_tests'][] = ['status' => 'OK', 'case' => 'SOA Retry value', 'info' => 'Good! Your SOA Retry value is within the recommended range (5-240 minutes).'];
        } else {
            $report['soa_tests'][] = ['status' => 'WARNING', 'case' => 'SOA Retry value', 'info' => 'Oops! Your SOA Retry value is outside the recommended range (5-240 minutes).'];
        }

        if ($soa['expire'] >= 604800 && $soa['expire'] <= 2419200) {
            $report['soa_tests'][] = ['status' => 'OK', 'case' => 'SOA Expire value', 'info' => 'Good! Your SOA Expire value is within the recommended range (1-4 weeks).'];
        } else {
            $report['soa_tests'][] = ['status' => 'WARNING', 'case' => 'SOA Expire value', 'info' => 'Oops! Your SOA Expire value is outside the recommended range (1-4 weeks).'];
        }

    } else {
        $report['soa_tests'][] = ['status' => 'FAIL', 'case' => 'SOA Record', 'info' => 'Could not retrieve SOA record.'];
    }

    // --- 4. Mail eXchanger (MX) Tests ---
    $mx_hosts = [];
    $mx_weights = [];
    $mx_records_exist = @getmxrr($domain, $mx_hosts, $mx_weights);

    if ($mx_records_exist) {
        $info = [];
        $mx_ips = [];
        for ($i = 0; $i < count($mx_hosts); $i++) {
            $ip = gethostbyname($mx_hosts[$i]);
            $mx_ips[$mx_hosts[$i]] = $ip;
            $info[] = "{$mx_weights[$i]} {$mx_hosts[$i]}.";
        }
        $report['mx_tests'][] = ['status' => 'INFO', 'case' => 'MX Records', 'info' => implode("\n", $info)];

        if (count($mx_hosts) >= 2) {
            $report['mx_tests'][] = ['status' => 'OK', 'case' => 'Number of MX records', 'info' => 'Good! You have at least 2 MX records.'];
        } else {
            $report['mx_tests'][] = ['status' => 'WARNING', 'case' => 'Number of MX records', 'info' => 'Warning! You only have one MX record, which is a single point of failure.'];
        }

        $all_mx_public = true;
        foreach ($mx_ips as $ip) { if (!is_public_ip($ip)) { $all_mx_public = false; break; } }
        if ($all_mx_public) {
            $report['mx_tests'][] = ['status' => 'OK', 'case' => 'All MX records use public IP addresses', 'info' => 'Good! All of your MX entries have public IP addresses.'];
        } else {
            $report['mx_tests'][] = ['status' => 'FAIL', 'case' => 'All MX records use public IP addresses', 'info' => 'Error! At least one of your MX entries has a private IP address.'];
        }
        
        if (count($mx_ips) === count(array_unique($mx_ips))) {
            $report['mx_tests'][] = ['status' => 'OK', 'case' => 'Duplicate MX A records', 'info' => 'Good! No two MX records resolve to the same IP address.'];
        } else {
            $report['mx_tests'][] = ['status' => 'WARNING', 'case' => 'Duplicate MX A records', 'info' => 'Warning! Some of your MX records resolve to the same IP address.'];
        }

    } else {
        $report['mx_tests'][] = ['status' => 'INFO', 'case' => 'MX Records', 'info' => 'No MX records found. This is normal if the domain does not handle email.'];
    }

    // --- 5. WWW Record Tests ---
    $www_domain = "www." . $domain;
    $www_a_records = @dns_get_record($www_domain, DNS_A);
    $www_cname_records = @dns_get_record($www_domain, DNS_CNAME);

    if ($www_a_records) {
        $info = [];
        $all_www_public = true;
        foreach ($www_a_records as $record) {
            $info[] = "{$www_domain}. A {$record['ip']} [TTL={$record['ttl']}]";
            if (!is_public_ip($record['ip'])) {
                $all_www_public = false;
            }
        }
        $report['www_tests'][] = ['status' => 'INFO', 'case' => 'WWW A record', 'info' => implode("\n", $info)];
        if ($all_www_public) {
            $report['www_tests'][] = ['status' => 'OK', 'case' => 'WWW A record has public IP', 'info' => 'Good! The IP address(es) for your WWW record are public.'];
        } else {
            $report['www_tests'][] = ['status' => 'FAIL', 'case' => 'WWW A record has public IP', 'info' => 'Error! At least one IP for your WWW record is private.'];
        }
    } elseif ($www_cname_records) {
        $info = [];
        foreach ($www_cname_records as $record) {
            $info[] = "{$www_domain}. CNAME {$record['target']} [TTL={$record['ttl']}]";
        }
        $report['www_tests'][] = ['status' => 'INFO', 'case' => 'WWW CNAME record', 'info' => implode("\n", $info)];
        $report['www_tests'][] = ['status' => 'OK', 'case' => 'WWW CNAME lookup', 'info' => 'OK! You have a CNAME entry for your WWW record.'];
    } else {
        $report['www_tests'][] = ['status' => 'INFO', 'case' => 'WWW record', 'info' => 'No A or CNAME record found for ' . $www_domain];
    }

    return $report;
}

?>