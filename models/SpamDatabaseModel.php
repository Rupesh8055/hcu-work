<?php
class SpamDatabaseModel {
    private $mysqli;
    private $dnsbls = [
        'zen.spamhaus.org',
        'sbl.spamhaus.org',
        'xbl.spamhaus.org',
        'pbl.spamhaus.org',
        'bl.spamcop.net',
        'cbl.abuseat.org',
        'dnsbl.sorbs.net',
        'multi.surbl.org',
        'dnsbl.dronebl.org',
        'dnsbl.spfbl.net'
    ];
    private $cache_file = __DIR__ . '/../logs/spam_cache.json';
    private $cache_expiry = 1800;
    private $timeout = 0.05;
    private $max_concurrent = 10;
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function checkDnsbls($query) {
        try {
            $start_time = microtime(true);
            $ip = $this->resolveQuery($query);
            if (!$ip) {
                return ['error' => 'Invalid IP address or domain. Please check your input and try again.'];
            }
            
            $cached_results = $this->getCache($ip);
            if ($cached_results) {
                $cached_results['cached'] = true;
                $cached_results['response_time'] = round((microtime(true) - $start_time) * 1000, 2);
                return $cached_results;
            }
            
            $reversedIp = implode('.', array_reverse(explode('.', $ip)));
            $results = $this->checkDnsblsParallel($reversedIp);
            
            if (empty($results)) {
                return ['error' => 'Unable to check any blacklists. Please try again later.'];
            }
            
            $listed_count = count(array_filter($results, function($r) { return $r['listed']; }));
            $total_checked = count($results);
            $response_time = round((microtime(true) - $start_time) * 1000, 2);
            
            $response = [
                'query' => $query,
                'resolved_ip' => $ip,
                'results' => $results,
                'summary' => [
                    'listed_count' => $listed_count,
                    'total_checks' => $total_checked,
                    'clean_count' => $total_checked - $listed_count,
                    'percentage_listed' => $total_checked > 0 ? round(($listed_count / $total_checked) * 100, 2) : 0,
                    'reputation_score' => $this->calculateReputationScore($listed_count, $total_checked),
                    'risk_level' => $this->getRiskLevel($listed_count, $total_checked),
                    'response_time' => $response_time
                ],
                'timestamp' => date('Y-m-d H:i:s'),
                'cached' => false,
                'blacklist_info' => $this->getBlacklistInfo()
            ];
            
            $this->setCache($ip, $response);
            return $response;
        } catch (Exception $e) {
            error_log("SpamDatabaseModel error: " . $e->getMessage());
            return ['error' => 'An error occurred while checking the blacklists. Please try again.'];
        }
    }

    private function checkDnsblsParallel($reversedIp) {
        if (!function_exists('curl_multi_init')) {
            return $this->checkDnsblsSequential($reversedIp);
        }
        
        $results = [];
        $multiHandle = curl_multi_init();
        $handles = [];
        
        foreach ($this->dnsbls as $dnsbl) {
            $lookup = $reversedIp . '.' . $dnsbl;
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => "http://" . $lookup,
                CURLOPT_TIMEOUT => $this->timeout,
                CURLOPT_CONNECTTIMEOUT => $this->timeout,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_NOBODY => true,
                CURLOPT_DNS_USE_GLOBAL_CACHE => false,
                CURLOPT_DNS_CACHE_TIMEOUT => 0,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_USERAGENT => 'SpamDatabaseChecker/3.0',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_FRESH_CONNECT => true,
                CURLOPT_FORBID_REUSE => true
            ]);
            
            $handles[$dnsbl] = $ch;
            curl_multi_add_handle($multiHandle, $ch);
        }
        
        $active = null;
        do {
            $mrc = curl_multi_exec($multiHandle, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);
        
        while ($active && $mrc == CURLM_OK) {
            if (curl_multi_select($multiHandle) != -1) {
                do {
                    $mrc = curl_multi_exec($multiHandle, $active);
                } while ($mrc == CURLM_CALL_MULTI_PERFORM);
            }
        }
        
        foreach ($this->dnsbls as $dnsbl) {
            if (isset($handles[$dnsbl])) {
                $ch = $handles[$dnsbl];
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $error = curl_error($ch);
                $response_time = curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000;
                $listed = ($httpCode == 200 || $httpCode == 127 || $httpCode == 302) && empty($error);
                
                $results[] = [
                    'dnsbl' => $dnsbl,
                    'listed' => $listed,
                    'status' => $listed ? 'Listed' : 'Clean',
                    'txt_record' => null,
                    'response_time' => round($response_time, 2),
                    'http_code' => $httpCode
                ];
                
                curl_multi_remove_handle($multiHandle, $ch);
                curl_close($ch);
                unset($handles[$dnsbl]);
            }
        }
        
        curl_multi_close($multiHandle);
        return $results;
    }
    
    private function checkDnsblsSequential($reversedIp) {
        $results = [];
        foreach ($this->dnsbls as $dnsbl) {
            $lookup = $reversedIp . '.' . $dnsbl;
            $result = $this->checkSingleDnsbl($lookup, $dnsbl);
            if ($result) {
                $results[] = $result;
            }
        }
        return $results;
    }

    private function checkSingleDnsbl($lookup, $dnsbl) {
        try {
            $start_time = microtime(true);
            $result = gethostbyname($lookup);
            $end_time = microtime(true);
            $response_time = round(($end_time - $start_time) * 1000, 2);
            $listed = ($result !== $lookup);
            
            return [
                'dnsbl' => $dnsbl,
                'listed' => $listed,
                'status' => $listed ? 'Listed' : 'Clean',
                'txt_record' => null,
                'response_time' => $response_time
            ];
        } catch (Exception $e) {
            error_log("DNSBL check failed for $dnsbl: " . $e->getMessage());
            return null;
        }
    }

    private function resolveQuery($query) {
        $query = trim($query);
        if (filter_var($query, FILTER_VALIDATE_IP)) {
            return $query;
        }
        if (filter_var($query, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $ip = gethostbyname($query);
            if ($ip && $ip !== $query) {
                return $ip;
            }
        }
        return false;
    }

    private function calculateReputationScore($listed_count, $total_checks) {
        if ($total_checks == 0) return 100;
        $percentage = ($listed_count / $total_checks) * 100;
        if ($percentage == 0) return 100;
        if ($percentage <= 5) return 95;
        if ($percentage <= 10) return 85;
        if ($percentage <= 20) return 70;
        if ($percentage <= 30) return 50;
        if ($percentage <= 50) return 25;
        return 0;
    }

    private function getRiskLevel($listed_count, $total_checks) {
        if ($total_checks == 0) return 'Unknown';
        $percentage = ($listed_count / $total_checks) * 100;
        if ($percentage == 0) return 'Clean';
        if ($percentage <= 5) return 'Low Risk';
        if ($percentage <= 10) return 'Medium Risk';
        if ($percentage <= 20) return 'High Risk';
        if ($percentage <= 30) return 'Very High Risk';
        return 'Critical Risk';
    }

    private function getCache($key) {
        if (!file_exists($this->cache_file)) {
            return null;
        }
        $cache_data = json_decode(file_get_contents($this->cache_file), true);
        if (!$cache_data || !isset($cache_data[$key])) {
            return null;
        }
        $cached_item = $cache_data[$key];
        if (time() - $cached_item['timestamp'] > $this->cache_expiry) {
            unset($cache_data[$key]);
            file_put_contents($this->cache_file, json_encode($cache_data));
            return null;
        }
        return $cached_item['data'];
    }

    private function setCache($key, $data) {
        $cache_data = [];
        if (file_exists($this->cache_file)) {
            $cache_data = json_decode(file_get_contents($this->cache_file), true) ?: [];
        }
        $cache_data[$key] = [
            'data' => $data,
            'timestamp' => time()
        ];
        if (count($cache_data) > 1000) {
            $cache_data = array_slice($cache_data, -1000, 1000, true);
        }
        file_put_contents($this->cache_file, json_encode($cache_data));
    }

    public function getBlacklistInfo() {
        return [
            'total_blacklists' => count($this->dnsbls),
            'categories' => [
                'spamhaus' => ['zen.spamhaus.org', 'sbl.spamhaus.org', 'xbl.spamhaus.org', 'pbl.spamhaus.org'],
                'major_providers' => ['bl.spamcop.net', 'cbl.abuseat.org', 'dnsbl.sorbs.net'],
                'additional' => ['multi.surbl.org', 'dnsbl.dronebl.org', 'dnsbl.spfbl.net']
            ],
            'description' => 'Ultra-fast spam database checker with 10 major DNS blacklists'
        ];
    }
}
?>