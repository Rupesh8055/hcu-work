<?php
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Includes/GeoIpSystem.php';

class IpLocationModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function locate($ip) {
        if (empty($ip)) return ['error' => 'IP address or domain is required.'];
        $originalInput = $ip;
        
        // Resolve domain to IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $host = parse_url($ip, PHP_URL_HOST) ?: $ip;
            if (strlen($host) > 255) {
                return ['error' => 'Invalid IP address or domain provided.'];
            }
            $resolvedIp = @gethostbyname($host);
            if ($resolvedIp === $host || !filter_var($resolvedIp, FILTER_VALIDATE_IP)) {
                return ['error' => 'Could not resolve domain to a valid IP.'];
            }
            $ip = $resolvedIp;
        }

        try {
            $geo = new GeoIpSystem($this->mysqli);
            $location_data = $geo->lookup($ip);

            // Accumulate progressive IP intelligence
            DatabaseManager::accumulateIpIntelligence($this->mysqli, $ip);

            if (!$location_data) {
                $location_data = [
                    'city' => 'Unknown', 'country' => 'Unknown', 'latitude' => 0, 'longitude' => 0,
                    'isp' => 'Unknown', 'organization' => 'Unknown', 'source' => 'internal_fallback'
                ];
            }

            return [
                'ip' => $ip,
                'original_input' => $originalInput !== $ip ? $originalInput : null,
                'location' => $location_data,
                'timestamp' => date('Y-m-d H:i:s'),
                'source' => $location_data['source'] ?? 'local_lookup'
            ];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while retrieving location information: ' . $e->getMessage()];
        }
    }
}