<?php

class RateLimiter {
    private $db;
    private $table = 'rate_limits';

    public function __construct($database) {
        $this->db = $database;
    }

    /**
     * Highly advanced rate limiter with dynamic weighting, individual IP tracking, 
     * and subnet-level distributed bot protection.
     * Implements "fail-open" pattern on database connection fluctuation.
     */
    public function check($ip, $tool = 'global', $ipLimit = 100, $subnetLimit = 500, $window = 3600, $cost = 1) {
        if (!$this->db || $this->db->connect_errno) {
            return true; // Fail open
        }

        try {
            // Garbage collection: 1% chance on lookup
            if (rand(1, 100) === 1) {
                $this->cleanup($window);
            }

            // 1. Calculate IP /24 subnet (or /64 for IPv6)
            $subnet = $ip;
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $parts = explode('.', $ip);
                if (count($parts) === 4) {
                    $subnet = $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
                }
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $parts = explode(':', $ip);
                if (count($parts) >= 4) {
                    $subnet = implode(':', array_slice($parts, 0, 4)) . '::/64';
                }
            }

            $now = time();

            // 2. Perform Single IP Rate Check
            $ipPass = $this->checkNode($ip, $tool, $ipLimit, $window, $cost, $now);
            if (!$ipPass) {
                return false; // Throttled at IP level
            }

            // 3. Perform Subnet Rate Check (bot protection)
            $subnetPass = $this->checkNode($subnet, $tool . '_subnet', $subnetLimit, $window, $cost, $now);
            if (!$subnetPass) {
                return false; // Throttled at Subnet level
            }

            return true;

        } catch (Throwable $e) {
            return true; // Fail open
        }
    }

    private function checkNode($node, $toolKey, $limit, $window, $cost, $now) {
        $stmt = $this->db->prepare("SELECT request_count, window_start FROM {$this->table} WHERE ip_address = ? AND tool = ? LIMIT 1");
        if (!$stmt) {
            return true; // Fail open
        }

        $stmt->bind_param('ss', $node, $toolKey);
        $stmt->execute();
        $result = $stmt->get_result();
        $record = $result->fetch_assoc();
        $stmt->close();

        if (!$record) {
            $stmtInsert = $this->db->prepare("INSERT INTO {$this->table} (ip_address, tool, request_count, window_start) VALUES (?, ?, ?, FROM_UNIXTIME(?))");
            if ($stmtInsert) {
                $stmtInsert->bind_param('ssii', $node, $toolKey, $cost, $now);
                $stmtInsert->execute();
                $stmtInsert->close();
            }
            return true;
        }

        $windowStart = strtotime($record['window_start']);
        if (($now - $windowStart) > $window) {
            $stmtUpdate = $this->db->prepare("UPDATE {$this->table} SET request_count = ?, window_start = FROM_UNIXTIME(?) WHERE ip_address = ? AND tool = ?");
            if ($stmtUpdate) {
                $stmtUpdate->bind_param('iiss', $cost, $now, $node, $toolKey);
                $stmtUpdate->execute();
                $stmtUpdate->close();
            }
            return true;
        }

        if (($record['request_count'] + $cost) > $limit) {
            return false; // Throttled!
        }

        $stmtIncrement = $this->db->prepare("UPDATE {$this->table} SET request_count = request_count + ? WHERE ip_address = ? AND tool = ?");
        if ($stmtIncrement) {
            $stmtIncrement->bind_param('iss', $cost, $node, $toolKey);
            $stmtIncrement->execute();
            $stmtIncrement->close();
        }
        return true;
    }

    private function cleanup($window) {
        if (!$this->db || $this->db->connect_errno) {
            return;
        }
        try {
            $cutoff = date('Y-m-d H:i:s', time() - $window);
            $stmt = $this->db->prepare("DELETE FROM {$this->table} WHERE window_start < ?");
            if ($stmt) {
                $stmt->bind_param('s', $cutoff);
                $stmt->execute();
                $stmt->close();
            }
        } catch (Throwable $e) {}
    }

    /**
     * Consume method compatible with token-bucket interface, wrapping check logic
     */
    public function consume($ip, $cost = 1, $tool = 'global', $ipLimit = 100) {
        $allowed = $this->check($ip, $tool, $ipLimit, 500, 3600, $cost);
        $remaining = $allowed ? max(0, $ipLimit - $cost) : 0;
        return ['allowed' => $allowed, 'remaining' => $remaining];
    }

    /**
     * Static tool cost mapping
     */
    public static function getToolCost($toolName) {
        $costs = [
            'dns-lookup'          => 1,
            'whois-lookup'        => 2,
            'reverse-ip-lookup'   => 5,
            'reverse-whois-lookup'=> 5,
            'ip-history'          => 5,
            'port-scanner'        => 10,
            'dns-report'          => 10,
            'investigator-mode'   => 10,
            'global-ping'         => 5
        ];

        return $costs[$toolName] ?? 1;
    }
}