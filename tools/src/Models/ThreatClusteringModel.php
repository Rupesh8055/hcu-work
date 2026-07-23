<?php

require_once __DIR__ . '/CorrelationEngineModel.php';
require_once __DIR__ . '/ReputationRiskModel.php';

class ThreatClusteringModel {
    private $mysqli;
    private $correlationModel;
    private $reputationModel;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->correlationModel = new CorrelationEngineModel($mysqli);
        $this->reputationModel = new ReputationRiskModel($mysqli);
    }

    /**
     * Identifies, clusters, and evaluates suspicious infrastructure neighborhoods.
     */
    public function detectThreatClusters($domain) {
        $domain = strtolower(trim($domain));
        if (empty($domain)) return ['error' => 'Domain required'];

        // 1. Fetch related domains via correlation engine
        $related = $this->correlationModel->findRelatedInfrastructure($domain);
        $ownFingerprint = $this->correlationModel->getFingerprint($domain);

        $clusters = [
            'mail_cluster' => [],
            'dns_cluster' => [],
            'subnet_cluster' => [],
            'corporate_cluster' => []
        ];

        $allMembers = [];
        $highRiskCount = 0;
        $totalRiskScore = 0;
        $anomalies = [];

        // 2. Classify relationships and check member risk
        foreach ($related as $rel) {
            $memberDomain = $rel['domain'];
            $overlaps = $rel['relationship_overlaps'];
            $similarity = $rel['similarity_percentage'];
            
            // Run a quick offline risk assessment
            $riskAssessment = $this->reputationModel->evaluate($memberDomain);
            $memberRisk = $riskAssessment['risk_score'] ?? 0;
            $totalRiskScore += $memberRisk;
            if ($memberRisk >= 50) {
                $highRiskCount++;
            }

            $memberInfo = [
                'domain' => $memberDomain,
                'similarity' => $similarity,
                'risk_score' => $memberRisk,
                'rating' => $riskAssessment['rating'] ?? 'Low Risk',
                'reasons' => $rel['overlap_indicators']
            ];

            // Allocate to clusters
            if (!empty($overlaps['mx_servers'])) {
                $clusters['mail_cluster'][] = $memberInfo;
            }
            if (!empty($overlaps['nameservers'])) {
                $clusters['dns_cluster'][] = $memberInfo;
            }
            if (!empty($overlaps['subnets'])) {
                $clusters['subnet_cluster'][] = $memberInfo;
            }
            if (isset($overlaps['registrar']) || isset($overlaps['organization'])) {
                $clusters['corporate_cluster'][] = $memberInfo;
            }

            $allMembers[] = $memberInfo;
        }

        // 3. Compute cluster heuristics
        $memberCount = count($allMembers);
        $averageRisk = $memberCount > 0 ? round($totalRiskScore / $memberCount, 1) : 0;

        // Threat Heuristics Score calculation (0 to 100)
        $threatIndex = 0;
        if ($memberCount > 0) {
            // Base score off average risk of neighboring infrastructure
            $threatIndex += $averageRisk * 0.5;
            // Additional risk if there's a high count of similar neighboring domains
            $threatIndex += min(20, $memberCount * 2);
            // Heavy penalty if high risk members are present
            if ($highRiskCount > 0) {
                $threatIndex += min(30, $highRiskCount * 10);
            }
        }

        // Check own risk indicators
        $ownRisk = $this->reputationModel->evaluate($domain);
        $ownRiskScore = $ownRisk['risk_score'] ?? 0;
        
        // Combine own risk and neighborhood threat indices
        $clusterThreatScore = round(min(100, ($threatIndex * 0.4) + ($ownRiskScore * 0.6)));

        // Flag visual anomalies
        if ($memberCount >= 10) {
            $anomalies[] = [
                'severity' => 'HIGH',
                'type' => 'Large Neighbor Footprint',
                'message' => "Extremely large infrastructure cluster detected ({$memberCount} connected nodes). Common in coordinated spam operations."
            ];
        }
        if ($highRiskCount > 2) {
            $anomalies[] = [
                'severity' => 'CRITICAL',
                'type' => 'Malicious Neighborhood',
                'message' => "Multiple high-risk domains ({$highRiskCount} nodes) share hosting resources or registration vectors with target."
            ];
        }
        if (!empty($ownFingerprint['nameservers'])) {
            foreach ($ownFingerprint['nameservers'] as $ns) {
                if (stripos($ns, 'free') !== false || stripos($ns, 'parking') !== false) {
                    $anomalies[] = [
                        'severity' => 'MEDIUM',
                        'type' => 'Suspicious Nameserver',
                        'message' => "Utilizing likely volatile or parked nameserver infrastructure: {$ns}."
                    ];
                }
            }
        }

        // General risk classification
        $threatLevel = 'Low Risk Cluster';
        if ($clusterThreatScore >= 75) {
            $threatLevel = 'High Risk / Hostile Infrastructure Cluster';
        } elseif ($clusterThreatScore >= 40) {
            $threatLevel = 'Suspicious Infrastructure / Volatile Network';
        }

        return [
            'target_domain' => $domain,
            'fingerprint' => $ownFingerprint,
            'clusters' => $clusters,
            'all_members' => $allMembers,
            'stats' => [
                'total_connected_domains' => $memberCount,
                'average_neighbor_risk' => $averageRisk,
                'high_risk_neighbors' => $highRiskCount,
                'own_risk_score' => $ownRiskScore
            ],
            'anomalies' => $anomalies,
            'cluster_threat_score' => $clusterThreatScore,
            'threat_level' => $threatLevel,
            'reputation_summary' => $ownRisk,
            'evaluated_at' => date('c')
        ];
    }
}
