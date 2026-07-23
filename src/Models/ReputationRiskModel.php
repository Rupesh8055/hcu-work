<?php

class ReputationRiskModel {
    private $mysqli;
    private $disposableMxDomains = [
        'mailinator.com', 'tempmail.com', 'dispostable.com', 'guerrillamail.com', 'yopmail.com',
        'sharklasers.com', 'guerrillamailblock.com', 'guerrillamail.net', 'guerrillamail.org',
        'guerrillamail.biz', 'grr.la', 'pokemail.net', 'trashmail.com', 'getairmail.com'
    ];

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function evaluate($domain, $dnsReport = null) {
        if (empty($domain)) return ['error' => 'Domain parameter required.'];

        $score = 100;
        $risks = [];
        $indicators = [];
        $confidence = 'Low';

        // 1. Analyze MX provider (Disposable Mail Check)
        $mxRecords = @dns_get_record($domain, DNS_MX);
        if (is_array($mxRecords)) {
            foreach ($mxRecords as $mx) {
                if (isset($mx['target'])) {
                    $mxHost = strtolower($mx['target']);
                    foreach ($this->disposableMxDomains as $disp) {
                        if (strpos($mxHost, $disp) !== false) {
                            $score -= 40;
                            $risks[] = "Domain utilizes disposable/temporary MX mail exchanger provider: {$disp}. High spam and compromise risk.";
                            $indicators[] = ['severity' => 'HIGH', 'category' => 'Mail Exchanger', 'message' => "Disposable MX server detected ($disp)"];
                        }
                    }
                }
            }
        }

        // 2. DNS SPF/DMARC spoofing checks
        $spfFound = false;
        $dmarcFound = false;
        $txts = @dns_get_record($domain, DNS_TXT);
        if (is_array($txts)) {
            foreach ($txts as $t) {
                $txtVal = $t['txt'] ?? ($t['entries'][0] ?? '');
                if (stripos($txtVal, 'v=spf1') !== false) {
                    $spfFound = true;
                    if (stripos($txtVal, '+all') !== false) {
                        $score -= 20;
                        $risks[] = "SPF record contains highly insecure '+all' wildcard authorization directive.";
                        $indicators[] = ['severity' => 'MEDIUM', 'category' => 'Spoofing Security', 'message' => "Insecure SPF '+all' directive"];
                    }
                }
            }
        }

        if (!$spfFound) {
            $score -= 15;
            $risks[] = "Missing SPF (Sender Policy Framework) record. Sub-optimal email authentication.";
            $indicators[] = ['severity' => 'MEDIUM', 'category' => 'Spoofing Security', 'message' => "Missing SPF record"];
        }

        $dmarc = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
        if (empty($dmarc)) {
            $score -= 15;
            $risks[] = "Missing DMARC policy record. Spoofing protection disabled.";
            $indicators[] = ['severity' => 'MEDIUM', 'category' => 'Spoofing Security', 'message' => "Missing DMARC record"];
        } else {
            $dmarcVal = $dmarc[0]['txt'] ?? ($dmarc[0]['entries'][0] ?? '');
            if (stripos($dmarcVal, 'p=none') !== false) {
                $score -= 10;
                $risks[] = "DMARC policy is set to monitoring 'p=none' (insecure).";
                $indicators[] = ['severity' => 'LOW', 'category' => 'Spoofing Security', 'message' => "Insecure DMARC policy (p=none)"];
            }
        }

        // 3. Dangling CNAME (Subdomain Takeover check)
        $cnames = @dns_get_record($domain, DNS_CNAME);
        if (is_array($cnames)) {
            $knownEndpoints = ['s3.amazonaws.com', 'github.io', 'herokuapp.com', 'myshopify.com', 'azurewebsites.net'];
            foreach ($cnames as $c) {
                if (isset($c['target'])) {
                    $target = strtolower($c['target']);
                    foreach ($knownEndpoints as $pattern) {
                        if (strpos($target, $pattern) !== false) {
                            $resolved = @gethostbyname($target);
                            if ($resolved === $target || empty($resolved)) {
                                $score -= 35;
                                $risks[] = "Potential subdomain takeover vulnerability on CNAME target: {$c['target']}. Destination host does not resolve.";
                                $indicators[] = ['severity' => 'CRITICAL', 'category' => 'Subdomain Takeover', 'message' => "Dangling CNAME target detected"];
                            }
                        }
                    }
                }
            }
        }

        // 4. Analyze recent IP history churn (Hosting volatility)
        $ipHistoryCount = 0;
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT COUNT(DISTINCT ip) as ip_count FROM ip_history WHERE domain = ?");
            if ($stmt) {
                $stmt->bind_param('s', $domain);
                $stmt->execute();
                $stmt->bind_result($ipHistoryCount);
                $stmt->fetch();
                $stmt->close();
                if ($ipHistoryCount > 4) {
                    $score -= 20;
                    $risks[] = "High IP address resolution volatility detected (historical churn rate: {$ipHistoryCount} distinct IPs). Potential fast-flux network behavior.";
                    $indicators[] = ['severity' => 'MEDIUM', 'category' => 'Hosting Volatility', 'message' => "High IP address churn ({$ipHistoryCount} IPs)"];
                }
            }
        }

        // 5. Nameserver snapshot volatility check
        $nsSnapshotsCount = 0;
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT COUNT(id) as ns_count FROM ns_snapshots WHERE domain_name = ?");
            if ($stmt) {
                $stmt->bind_param('s', $domain);
                $stmt->execute();
                $stmt->bind_result($nsSnapshotsCount);
                $stmt->fetch();
                $stmt->close();
                if ($nsSnapshotsCount > 3) {
                    $score -= 30;
                    $risks[] = "Rapid Nameserver migration transitions detected (NS migrations logged: {$nsSnapshotsCount}). Potential domain hijacking or volatile hosting rotations.";
                    $indicators[] = ['severity' => 'HIGH', 'category' => 'Infrastructure Volatility', 'message' => "Rapid Nameserver transitions"];
                }
            }
        }

        // 6. Neighborhood overlap (Shared nameserver / subnet spam indicators)
        if ($this->mysqli) {
            // Find other domains on the same nameservers and see if they utilize disposable mail
            $stmt = $this->mysqli->prepare("SELECT DISTINCT domain FROM ns_mapping WHERE nameserver IN (SELECT nameserver FROM ns_mapping WHERE domain = ?) AND domain != ? LIMIT 30");
            if ($stmt) {
                $stmt->bind_param('ss', $domain, $domain);
                $stmt->execute();
                $res = $stmt->get_result();
                $sharedDomains = [];
                while ($row = $res->fetch_assoc()) {
                    $sharedDomains[] = $row['domain'];
                }
                $stmt->close();

                $neighborhoodSpamCount = 0;
                foreach ($sharedDomains as $sd) {
                    $stmt = $this->mysqli->prepare("SELECT COUNT(*) FROM mx_mapping WHERE domain = ? AND mx_server LIKE '%mailinator%'");
                    if ($stmt) {
                        $stmt->bind_param('s', $sd);
                        $stmt->execute();
                        $stmt->bind_result($cnt);
                        if ($stmt->fetch() && $cnt > 0) {
                            $neighborhoodSpamCount++;
                        }
                        $stmt->close();
                    }
                }

                if ($neighborhoodSpamCount > 1) {
                    $score -= 25;
                    $risks[] = "Shared bad neighborhood overlap: {$neighborhoodSpamCount} domains hosted on the same infrastructure share spam/disposable indicators.";
                    $indicators[] = ['severity' => 'MEDIUM', 'category' => 'Infrastructure Overlap', 'message' => "Bad neighborhood infrastructure overlap"];
                }
            }
        }

        // Determine Confidence Level
        $totalTimelineLogs = $ipHistoryCount + $nsSnapshotsCount;
        if ($totalTimelineLogs > 5) {
            $confidence = 'High';
        } elseif ($totalTimelineLogs > 1) {
            $confidence = 'Medium';
        } else {
            $confidence = 'Low (Incomplete historical footprint datasets)';
        }

        // Normalize trust score bounds
        $score = max(0, min(100, $score));
        $riskScore = 100 - $score;

        $rating = 'Low Risk';
        if ($score < 40) $rating = 'Critical Risk';
        elseif ($score < 70) $rating = 'Medium Risk';
        elseif ($score < 90) $rating = 'Low-Medium Risk';

        return [
            'domain' => $domain,
            'trust_score' => $score,
            'risk_score' => $riskScore,
            'confidence_level' => $confidence,
            'rating' => $rating,
            'risk_indicators' => $indicators,
            'risks' => $risks,
            'evaluated_at' => date('c')
        ];
    }
}
