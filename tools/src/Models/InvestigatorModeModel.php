<?php

require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Includes/GeoIpSystem.php';
require_once __DIR__ . '/DnsLookupModel.php';
require_once __DIR__ . '/WhoisLookupModel.php';
require_once __DIR__ . '/HistoricalIntelligenceModel.php';
require_once __DIR__ . '/ThreatClusteringModel.php';
require_once __DIR__ . '/ReputationRiskModel.php';


class InvestigatorModeModel {
    private $mysqli;
    private $dnsModel;
    private $whoisModel;
    private $historyModel;
    private $threatModel;
    private $riskModel;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->dnsModel = new DnsLookupModel($mysqli);
        $this->whoisModel = new WhoisLookupModel($mysqli);
        $this->historyModel = new HistoricalIntelligenceModel($mysqli);
        $this->threatModel = new ThreatClusteringModel($mysqli);
        $this->riskModel = new ReputationRiskModel($mysqli);
    }

    /**
     * Performs a comprehensive multi-layered intelligence scan of a target node.
     */
    public function investigate($query) {
        $query = strtolower(trim($query));
        if (empty($query)) {
            return ['error' => 'Query is required.'];
        }

        $isIp = filter_var($query, FILTER_VALIDATE_IP);
        $dossier = [
            'target' => $query,
            'type' => $isIp ? 'IP' : 'Domain',
            'timestamp' => date('c'),
            'dns_data' => null,
            'whois_data' => null,
            'timeline' => [],
            'threat_clusters' => null,
            'reputation' => null,
            'network_context' => null
        ];

        if ($isIp) {
            // 1. IP Target Investigation
            // Geolocation and offline RIR ranges lookup
            $geo = new GeoIpSystem($this->mysqli);
            $locData = $geo->lookup($query);
            
            $ipLong = ip2long($query);
            $ipNum = sprintf('%u', $ipLong);
            $cidr = 'Unknown';
            $asn = 'Unknown';
            $org = 'Unknown';
            $registry = 'Unknown';
            $country = 'Unknown';

            if ($this->mysqli) {
                $stmt = $this->mysqli->prepare("SELECT cidr, country_code, asn, isp_org, registry FROM ip_ranges WHERE ? >= start_ip_num AND ? <= end_ip_num LIMIT 1");
                if ($stmt) {
                    $stmt->bind_param('ss', $ipNum, $ipNum);
                    $stmt->execute();
                    $stmt->bind_result($dbCidr, $dbCc, $dbAsn, $dbOrg, $dbRegistry);
                    if ($stmt->fetch()) {
                        $cidr = $dbCidr;
                        $country = $dbCc;
                        $asn = $dbAsn ? 'AS' . $dbAsn : 'Unknown';
                        $org = $dbOrg;
                        $registry = $dbRegistry;
                    }
                    $stmt->close();
                }
            }

            // Fallback to geoip details if database ranges are missing
            if ($locData && $org === 'Unknown') {
                $org = $locData['organization'] !== 'Unknown' ? $locData['organization'] : $locData['isp'];
                $country = $locData['country'];
            }

            $ptr = @gethostbyaddr($query);
            
            // Find domains hosted on this IP in ip_history
            $hostedDomains = [];
            if ($this->mysqli) {
                $stmt = $this->mysqli->prepare("SELECT DISTINCT domain, MAX(timestamp) as last_seen FROM ip_history WHERE ip = ? GROUP BY domain LIMIT 50");
                if ($stmt) {
                    $stmt->bind_param('s', $query);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    while ($row = $res->fetch_assoc()) {
                        $hostedDomains[] = [
                            'domain' => $row['domain'],
                            'last_seen' => $row['last_seen']
                        ];
                    }
                    $stmt->close();
                }
            }

            // Synthesize reputation and threat indicators for the IP
            $ipRisks = [];
            $ipIndicators = [];
            $ipScore = 100;

            if (count($hostedDomains) > 10) {
                $ipScore -= 20;
                $ipRisks[] = "Highly crowded IP hosting node (hosting over 10 distinct domains). Potential shared or bulletproof hosting environment.";
                $ipIndicators[] = ['severity' => 'MEDIUM', 'category' => 'Infrastructure Crowding', 'message' => "High domain co-location count (" . count($hostedDomains) . ")"];
            }

            // Is ISP high-risk?
            if (stripos($org, 'hosting') !== false || stripos($org, 'cloud') !== false || stripos($org, 'digitalocean') !== false || stripos($org, 'ovh') !== false) {
                $ipScore -= 10;
                $ipRisks[] = "IP originates from a cloud/hosting datacenter network. Highly prone to temporary scraper or bot hosting.";
                $ipIndicators[] = ['severity' => 'LOW', 'category' => 'Network Class', 'message' => "Datacenter/VPS network detected"];
            }

            $ipScore = max(0, $ipScore);
            $rating = 'Low Risk';
            if ($ipScore < 50) $rating = 'High Risk';
            elseif ($ipScore < 80) $rating = 'Medium Risk';

            $dossier['reputation'] = [
                'trust_score' => $ipScore,
                'risk_score' => 100 - $ipScore,
                'rating' => $rating,
                'risks' => $ipRisks,
                'risk_indicators' => $ipIndicators,
                'evaluated_at' => date('c')
            ];

            $dossier['network_context'] = [
                'ip' => $query,
                'ptr_record' => $ptr,
                'cidr' => $cidr,
                'asn' => $asn,
                'organization' => $org,
                'registry' => $registry,
                'country' => $country,
                'latitude' => $locData['latitude'] ?? null,
                'longitude' => $locData['longitude'] ?? null,
                'hosted_domains_count' => count($hostedDomains),
                'hosted_domains' => $hostedDomains
            ];

        } else {
            // 2. Domain Target Investigation
            // Trigger background resolutions if needed, but here we run active resolver to guarantee fresh dataset
            $dnsRes = $this->dnsModel->lookup($query);
            $whoisRes = $this->whoisModel->lookup($query);

            $dossier['dns_data'] = isset($dnsRes['error']) ? null : $dnsRes;
            $dossier['whois_data'] = isset($whoisRes['error']) ? null : $whoisRes;

            // Generate chronological snapshot difference timelines
            $dossier['timeline'] = $this->historyModel->getMasterTimeline($query);

            // Compute Threat Clustering mappings
            $dossier['threat_clusters'] = $this->threatModel->detectThreatClusters($query);

            // Compute Reputation Risk scoring scorecard
            $dossier['reputation'] = $this->riskModel->evaluate($query, $dnsRes);

            // Fetch IP location contexts for A records
            $ips = [];
            if ($dnsRes && isset($dnsRes['records'])) {
                foreach ($dnsRes['records'] as $r) {
                    if ($r['type'] === 'A' && filter_var($r['data'], FILTER_VALIDATE_IP)) {
                        $ips[] = $r['data'];
                    }
                }
            }

            $ipContexts = [];
            $geo = new GeoIpSystem($this->mysqli);
            foreach ($ips as $ip) {
                $loc = $geo->lookup($ip);
                $ipContexts[$ip] = [
                    'ip' => $ip,
                    'location' => $loc ? ($loc['city'] . ', ' . $loc['country']) : 'Unknown',
                    'organization' => $loc ? $loc['organization'] : 'Unknown',
                    'latitude' => $loc ? $loc['latitude'] : null,
                    'longitude' => $loc ? $loc['longitude'] : null
                ];
            }
            $dossier['network_context'] = [
                'resolved_ips' => $ipContexts
            ];
        }

        return $dossier;
    }
}
