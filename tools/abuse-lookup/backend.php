<?php
// Backend for Abuse Contact Lookup Tool

function find_abuse_contact($query)
{
    // Input validation
    if (!filter_var($query, FILTER_VALIDATE_IP) && !filter_var($query, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return ['error' => 'Invalid input. Please provide a valid IP address or domain name.'];
    }

    // 1. Get main WHOIS info for the original query (IP or domain)
    $whois_output = shell_exec("whois " . escapeshellarg($query));
    if (empty($whois_output)) {
        return ['error' => "Could not retrieve WHOIS information for: " . htmlspecialchars($query)];
    }

    // 2. Get abuse.net info
    $abuse_net_output = shell_exec("whois -h whois.abuse.net " . escapeshellarg($query));

    // --- Parsing ---
    $results = [
        'registrar' => null,
        'whois_abuse' => null,
        'abuse_net' => null,
        'full_record' => $whois_output // Fallback
    ];
    $email_pattern = '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/';

    // Parse main WHOIS output
    $lines = explode("\n", $whois_output);
    foreach ($lines as $line) {
        if (preg_match('/^Registrar:\s*(.*)$/i', $line, $matches)) {
            $results['registrar'] = trim($matches[1]);
        }
        if (stripos($line, 'abuse') !== false && preg_match($email_pattern, $line, $matches)) {
            if (is_null($results['whois_abuse'])) { // Get the first abuse email found
                $results['whois_abuse'] = trim($matches[0]);
            }
        }
    }

    // Parse abuse.net output
    if (!empty($abuse_net_output)) {
        if (preg_match($email_pattern, $abuse_net_output, $matches)) {
            $results['abuse_net'] = trim($matches[0]);
        }
    }

    return $results;
}
?>