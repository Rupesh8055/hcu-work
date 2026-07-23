<?php

class HistoricalIntelligenceModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    /**
     * Diffs chronological WHOIS snapshots to produce a readable event timeline.
     */
    public function diffWhoisSnapshots($domain) {
        $domain = strtolower(trim($domain));
        if (empty($domain)) return [];

        $timeline = [];
        if (!$this->mysqli) return $timeline;

        $stmt = $this->mysqli->prepare("SELECT registrar, abuse_email, organization, nameserver, timestamp FROM whois_snapshots WHERE domain_name = ? ORDER BY timestamp ASC");
        if (!$stmt) return [];

        $stmt->bind_param('s', $domain);
        $stmt->execute();
        $res = $stmt->get_result();
        $snapshots = [];
        while ($row = $res->fetch_assoc()) {
            $snapshots[] = $row;
        }
        $stmt->close();

        if (empty($snapshots)) {
            return [];
        }

        $prev = null;
        foreach ($snapshots as $index => $snap) {
            $timestamp = $snap['timestamp'];
            $changes = [];

            if ($index === 0) {
                // Initial observed state
                $changes[] = "Initial observed footprint: Registered with " . ($snap['registrar'] ?: 'Unknown Registrar') . 
                             ($snap['organization'] ? " by " . $snap['organization'] : "") . ".";
                if (!empty($snap['nameserver'])) {
                    $changes[] = "Nameservers configured: " . $snap['nameserver'];
                }
                $timeline[] = [
                    'timestamp' => $timestamp,
                    'event' => 'Initial Observation',
                    'changes' => $changes,
                    'details' => [
                        'registrar' => $snap['registrar'],
                        'organization' => $snap['organization'],
                        'nameserver' => $snap['nameserver'],
                        'abuse_email' => $snap['abuse_email']
                    ]
                ];
            } else {
                // Compare with previous snapshot
                if ($snap['registrar'] !== $prev['registrar']) {
                    $changes[] = "Registrar migrated from '" . ($prev['registrar'] ?: 'None') . "' to '" . ($snap['registrar'] ?: 'None') . "'.";
                }
                if ($snap['organization'] !== $prev['organization']) {
                    $changes[] = "Organization transitioned from '" . ($prev['organization'] ?: 'None') . "' to '" . ($snap['organization'] ?: 'None') . "'.";
                }
                if ($snap['abuse_email'] !== $prev['abuse_email']) {
                    $changes[] = "Abuse contact email updated from '" . ($prev['abuse_email'] ?: 'None') . "' to '" . ($snap['abuse_email'] ?: 'None') . "'.";
                }
                
                $prevNsList = !empty($prev['nameserver']) ? array_map('trim', explode(',', $prev['nameserver'])) : [];
                $currNsList = !empty($snap['nameserver']) ? array_map('trim', explode(',', $snap['nameserver'])) : [];
                sort($prevNsList);
                sort($currNsList);

                if ($prevNsList !== $currNsList) {
                    $added = array_diff($currNsList, $prevNsList);
                    $removed = array_diff($prevNsList, $currNsList);
                    $nsChanges = [];
                    if (!empty($added)) {
                        $nsChanges[] = "added " . implode(', ', $added);
                    }
                    if (!empty($removed)) {
                        $nsChanges[] = "removed " . implode(', ', $removed);
                    }
                    $changes[] = "Nameservers updated: " . implode(' and ', $nsChanges) . ".";
                }

                if (!empty($changes)) {
                    $timeline[] = [
                        'timestamp' => $timestamp,
                        'event' => 'WHOIS Domain Transition',
                        'changes' => $changes,
                        'details' => [
                            'registrar' => $snap['registrar'],
                            'organization' => $snap['organization'],
                            'nameserver' => $snap['nameserver'],
                            'abuse_email' => $snap['abuse_email']
                        ]
                    ];
                }
            }
            $prev = $snap;
        }

        return $timeline;
    }

    /**
     * Diffs chronological DNS snapshots grouped by record type.
     */
    public function diffDnsSnapshots($domain) {
        $domain = strtolower(trim($domain));
        if (empty($domain)) return [];

        $timeline = [];
        if (!$this->mysqli) return $timeline;

        $stmt = $this->mysqli->prepare("SELECT record_type, record_data, timestamp FROM dns_snapshots WHERE domain_name = ? ORDER BY timestamp ASC");
        if (!$stmt) return [];

        $stmt->bind_param('s', $domain);
        $stmt->execute();
        $res = $stmt->get_result();
        $snapshotsByType = [];
        while ($row = $res->fetch_assoc()) {
            $type = strtoupper($row['record_type']);
            $snapshotsByType[$type][] = [
                'data' => json_decode($row['record_data'], true) ?: [],
                'timestamp' => $row['timestamp']
            ];
        }
        $stmt->close();

        foreach ($snapshotsByType as $type => $snaps) {
            $prev = null;
            foreach ($snaps as $index => $snap) {
                $timestamp = $snap['timestamp'];
                $changes = [];

                // Extract targets
                $currTargets = [];
                foreach ($snap['data'] as $rec) {
                    if (isset($rec['data'])) {
                        $currTargets[] = $rec['data'];
                    }
                }
                sort($currTargets);

                if ($index === 0) {
                    $changes[] = "Initial observed DNS $type record: [" . implode(', ', $currTargets) . "]";
                    $timeline[] = [
                        'timestamp' => $timestamp,
                        'event' => "DNS $type record initialized",
                        'record_type' => $type,
                        'changes' => $changes,
                        'targets' => $currTargets
                    ];
                } else {
                    $prevTargets = [];
                    foreach ($prev['data'] as $rec) {
                        if (isset($rec['data'])) {
                            $prevTargets[] = $rec['data'];
                        }
                    }
                    sort($prevTargets);

                    if ($prevTargets !== $currTargets) {
                        $added = array_diff($currTargets, $prevTargets);
                        $removed = array_diff($prevTargets, $currTargets);
                        if (!empty($added)) {
                            $changes[] = "Added targets: " . implode(', ', $added);
                        }
                        if (!empty($removed)) {
                            $changes[] = "Removed targets: " . implode(', ', $removed);
                        }
                        if (!empty($changes)) {
                            $timeline[] = [
                                'timestamp' => $timestamp,
                                'event' => "DNS $type record modified",
                                'record_type' => $type,
                                'changes' => $changes,
                                'targets' => $currTargets
                            ];
                        }
                    }
                }
                $prev = $snap;
            }
        }

        // Sort combined DNS timeline descending or ascending by timestamp
        usort($timeline, function($a, $b) {
            return strcmp($a['timestamp'], $b['timestamp']);
        });

        return $timeline;
    }

    /**
     * Diffs chronological Nameserver snapshots.
     */
    public function diffNsSnapshots($domain) {
        $domain = strtolower(trim($domain));
        if (empty($domain)) return [];

        $timeline = [];
        if (!$this->mysqli) return $timeline;

        $stmt = $this->mysqli->prepare("SELECT nameservers, timestamp FROM ns_snapshots WHERE domain_name = ? ORDER BY timestamp ASC");
        if (!$stmt) return [];

        $stmt->bind_param('s', $domain);
        $stmt->execute();
        $res = $stmt->get_result();
        $snapshots = [];
        while ($row = $res->fetch_assoc()) {
            $snapshots[] = $row;
        }
        $stmt->close();

        $prev = null;
        foreach ($snapshots as $index => $snap) {
            $timestamp = $snap['timestamp'];
            $changes = [];

            $currNsList = !empty($snap['nameservers']) ? array_map('trim', explode(',', $snap['nameservers'])) : [];
            sort($currNsList);

            if ($index === 0) {
                $changes[] = "Initial active nameserver cluster: [" . implode(', ', $currNsList) . "]";
                $timeline[] = [
                    'timestamp' => $timestamp,
                    'event' => 'Nameservers Observed',
                    'changes' => $changes,
                    'nameservers' => $currNsList
                ];
            } else {
                $prevNsList = !empty($prev['nameservers']) ? array_map('trim', explode(',', $prev['nameservers'])) : [];
                sort($prevNsList);

                if ($prevNsList !== $currNsList) {
                    $added = array_diff($currNsList, $prevNsList);
                    $removed = array_diff($prevNsList, $currNsList);
                    if (!empty($added)) {
                        $changes[] = "Added nameservers: " . implode(', ', $added);
                    }
                    if (!empty($removed)) {
                        $changes[] = "Removed nameservers: " . implode(', ', $removed);
                    }
                    $timeline[] = [
                        'timestamp' => $timestamp,
                        'event' => 'Nameserver Cluster Migration',
                        'changes' => $changes,
                        'nameservers' => $currNsList
                    ];
                }
            }
            $prev = $snap;
        }

        return $timeline;
    }

    /**
     * Aggregates all chronological snapshots to generate a unified Master Intelligence Timeline.
     */
    public function getMasterTimeline($domain) {
        $whois = $this->diffWhoisSnapshots($domain);
        $dns = $this->diffDnsSnapshots($domain);
        $ns = $this->diffNsSnapshots($domain);

        $unified = [];

        foreach ($whois as $item) {
            $unified[] = [
                'timestamp' => $item['timestamp'],
                'source' => 'WHOIS Snapshot',
                'event' => $item['event'],
                'changes' => $item['changes'],
                'importance' => 'HIGH'
            ];
        }

        foreach ($dns as $item) {
            $unified[] = [
                'timestamp' => $item['timestamp'],
                'source' => 'DNS Snapshot (' . $item['record_type'] . ')',
                'event' => $item['event'],
                'changes' => $item['changes'],
                'importance' => 'MEDIUM'
            ];
        }

        foreach ($ns as $item) {
            $unified[] = [
                'timestamp' => $item['timestamp'],
                'source' => 'Nameserver Snapshot',
                'event' => $item['event'],
                'changes' => $item['changes'],
                'importance' => 'HIGH'
            ];
        }

        // Sort chronologically ascending
        usort($unified, function($a, $b) {
            return strcmp($a['timestamp'], $b['timestamp']);
        });

        return $unified;
    }
}
