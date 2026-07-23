<?php
require_once __DIR__ . '/../security/SecurityUtils.php';
class SiteDownCheckerModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    private function resolve_dns($hostname) {
        $ips = gethostbynamel($hostname);
        if ($ips === false) {
            return ['status' => 'fail', 'details' => 'DNS resolution failed.'];
        }
        return ['status' => 'ok', 'details' => 'Resolves to: ' . implode(', ', $ips), 'ips' => $ips];
    }
    private function ping_host($ip) {
        $ping_result = '';
        $ping_status = 'fail';

        if (function_exists('exec')) {
            $ping_cmd = '';
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $ping_cmd = "ping -n 1 -w 1000 " . escapeshellarg($ip) . " 2>&1";
            } else {
                $ping_cmd = "ping -c 1 -W 1 " . escapeshellarg($ip) . " 2>&1";
            }

            $output = [];
            $return_var = 0;
            exec($ping_cmd, $output, $return_var);

            if ($return_var === 0 && !empty($output)) {
                $ping_result = implode("\n", $output);
                $ping_status = 'ok';
            } else {
                $connection = @fsockopen($ip, 80, $errno, $errstr, 1);
                if (is_resource($connection)) {
                    fclose($connection);
                    $ping_result = "Server responds to HTTP connection test on port 80";
                    $ping_status = 'ok';
                } else {
                    $connection = @fsockopen($ip, 443, $errno, $errstr, 1);
                    if (is_resource($connection)) {
                        fclose($connection);
                        $ping_result = "Server responds to HTTPS connection test on port 443";
                        $ping_status = 'ok';
                    } else {
                        $ping_result = "No response to ping or connection tests";
                        $ping_status = 'fail';
                    }
                }
            }
        } else {
            $connection = @fsockopen($ip, 80, $errno, $errstr, 1);
            if (is_resource($connection)) {
                fclose($connection);
                $ping_result = "Server responds to HTTP connection test on port 80";
                $ping_status = 'ok';
            } else {
                $connection = @fsockopen($ip, 443, $errno, $errstr, 1);
                if (is_resource($connection)) {
                    fclose($connection);
                    $ping_result = "Server responds to HTTPS connection test on port 443";
                    $ping_status = 'ok';
                } else {
                    $ping_result = "No response to connection tests";
                    $ping_status = 'fail';
                }
            }
        }

        return ['status' => $ping_status, 'details' => $ping_result];
    }
    private function check_port($ip, $port) {
        $connection = @fsockopen($ip, $port, $errno, $errstr, 1);
        if (is_resource($connection)) {
            fclose($connection);
            return ['status' => 'open'];
        }
        return ['status' => 'closed'];
    }

    private function getTroubleshootingSteps() {
        return [
            'Clear all cookies/history in your browser.',
            'Restart your PC and Internet modem.',
            'Flush your local DNS cache:',
            'For Windows, run the command `ipconfig /flushdns`',
            'For Mac OSX (Leopard), run the command `dscacheutil -flushcache`',
            'For Mac OSX (<10.5.1), run the command `lookupd -flushcache`',
            'For Linux, run the command `/etc/init.d/nscd restart`',
            'Check that there are no DNS propagation errors by using our <a href="../dns-propagation/">DNS Propagation Checker</a>.'
        ];
    }
    private function fetch_http_status($url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_NOBODY, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; SiteDownChecker/1.0)');
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $start_time = microtime(true);
        $response = curl_exec($ch);
        $end_time = microtime(true);
        $response_time = round(($end_time - $start_time) * 1000, 2);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($curl_error) {
            return [
                'status' => 'fail',
                'details' => 'CURL Error: ' . $curl_error,
                'response_time' => $response_time
            ];
        }

        $site_title = 'Unknown';
        if ($response && $http_code >= 200 && $http_code < 400) {
            if (preg_match('/<title[^>]*>(.*?)<\/title>/i', $response, $matches)) {
                $raw_title = trim($matches[1]);
                $sanitized_title = SecurityUtils::sanitizeInput($raw_title, 'general', 50);
                if ($sanitized_title !== false) {
                    $site_title = $sanitized_title;
                    if (strlen($site_title) > 50) {
                        $site_title = substr($site_title, 0, 47) . '...';
                    }
                } else {
                    $site_title = html_entity_decode($raw_title, ENT_QUOTES, 'UTF-8');
                    $site_title = preg_replace('/[<>]/', '', $site_title);
                    if (strlen($site_title) > 50) {
                        $site_title = substr($site_title, 0, 47) . '...';
                    }
                }
            }
        }

        if ($http_code >= 200 && $http_code < 400) {
            return [
                'status' => 'ok',
                'details' => "HTTP {$http_code} - Site is accessible",
                'http_code' => $http_code,
                'response_time' => $response_time,
                'site_title' => $site_title
            ];
        } else {
            return [
                'status' => 'fail',
                'details' => "HTTP {$http_code} - Site may be experiencing issues",
                'http_code' => $http_code,
                'response_time' => $response_time,
                'site_title' => $site_title
            ];
        }
    }
    public function check($url) {
        if (!preg_match('/^https?:\/\//', $url)) {
            $url = 'https://' . $url;
        }

        if (!SecurityUtils::validateURL($url)) {
            return ['error' => 'Invalid URL format provided.'];
        }
        
        $suspiciousPattern = SecurityUtils::detectSuspiciousPatterns($url);
        if ($suspiciousPattern) {
            error_log("Suspicious pattern detected in site-down-checker: " . $suspiciousPattern . " - URL: " . substr($url, 0, 100));
            return ['error' => 'Invalid input detected.'];
        }
        $parsed_url = parse_url($url);
        if (!$parsed_url || !isset($parsed_url['host'])) {
            return ['error' => 'Unable to parse URL.'];
        }
        $hostname = $parsed_url['host'];
        $port = isset($parsed_url['port']) ? $parsed_url['port'] : (isset($parsed_url['scheme']) && $parsed_url['scheme'] === 'https' ? 443 : 80);
        $results = [];
        $dns_result = $this->resolve_dns($hostname);
        $results['dns'] = $dns_result;
        if ($dns_result['status'] === 'ok' && isset($dns_result['ips'])) {
            $primary_ip = $dns_result['ips'][0];
            $ping_result = $this->ping_host($primary_ip);
            $results['connectivity'] = $ping_result;
            $port_result = $this->check_port($primary_ip, $port);
            $results['port'] = $port_result;
            $http_result = $this->fetch_http_status($url);
            $results['http'] = $http_result;
            $overall_status = 'ok';
            $issues = [];
            if ($dns_result['status'] === 'fail') {
                $overall_status = 'fail';
                $issues[] = 'DNS resolution failed';
            }
            if ($ping_result['status'] === 'fail') {
                $overall_status = 'fail';
                $issues[] = 'No connectivity';
            }
            if ($port_result['status'] === 'closed') {
                $overall_status = 'fail';
                $issues[] = 'Port is closed';
            }
            if ($http_result['status'] === 'fail') {
                $overall_status = 'fail';
                $issues[] = 'HTTP error: ' . ($http_result['http_code'] ?? 'Unknown');
            }
            $results['overall'] = [
                'status' => $overall_status,
                'summary' => $overall_status === 'ok' ? 'Site is accessible' : 'Site has issues: ' . implode(', ', $issues)
            ];
        } else {
            $results['overall'] = [
                'status' => 'fail',
                'summary' => 'DNS resolution failed - cannot check site status'
            ];

            $formatted_results = [];
            $formatted_results[] = [
                'test' => 'DNS resolves for your hostname',
                'details' => 'DNS resolution failed',
                'status' => $results['dns']['status']
            ];

            $summary_text = "The site {$hostname} appears to be down or experiencing issues. Please try the following:";

            return [
                'results' => $formatted_results,
                'summary' => $summary_text,
                'troubleshooting_steps' => $this->getTroubleshootingSteps(),
                'overall_status' => $results['overall']['status']
            ];
        }
        $formatted_results = [];
        $formatted_results[] = [
            'test' => 'DNS resolves for your hostname',
            'details' => $results['dns']['status'] === 'ok' ? 'Your site resolves to the following IP address(es): ' . implode(', ', $results['dns']['ips']) : 'DNS resolution failed',
            'status' => $results['dns']['status']
        ];

        if (isset($results['connectivity'])) {
            $formatted_results[] = [
                'test' => 'Your server responds to pings',
                'details' => $results['connectivity']['details'],
                'status' => $results['connectivity']['status']
            ];
        }

        if (isset($results['port'])) {
            $port_80_status = $this->check_port($primary_ip, 80);
            $port_443_status = $this->check_port($primary_ip, 443);

            $port_details = '';
            if ($port_80_status['status'] === 'open' && $port_443_status['status'] === 'open') {
                $port_details = 'Port 80 is OPEN, Port 443 is OPEN';
                $port_status = 'ok';
            } elseif ($port_80_status['status'] === 'open') {
                $port_details = 'Port 80 is OPEN, Port 443 is CLOSED';
                $port_status = 'ok';
            } elseif ($port_443_status['status'] === 'open') {
                $port_details = 'Port 80 is CLOSED, Port 443 is OPEN';
                $port_status = 'ok';
            } else {
                $port_details = 'Port 80 is CLOSED, Port 443 is CLOSED';
                $port_status = 'fail';
            }

            $formatted_results[] = [
                'test' => 'Check that webserver ports are open',
                'details' => $port_details,
                'status' => $port_status
            ];
        }

        if (isset($results['http'])) {
            $site_title = isset($results['http']['site_title']) ? $results['http']['site_title'] : 'Unknown';
            $formatted_results[] = [
                'test' => 'Retrieve site title',
                'details' => $results['http']['status'] === 'ok' ? $site_title : 'Failed to retrieve site title',
                'status' => $results['http']['status'] === 'ok' ? 'info' : 'fail'
            ];
        }

        $summary_text = '';
        if ($results['overall']['status'] === 'ok') {
            $summary_text = "The site {$hostname} appears to be working fine. If you are still having trouble seeing it, please try the following:";
        } else {
            $summary_text = "The site {$hostname} appears to be down or experiencing issues. Please try the following:";
        }

        return [
            'results' => $formatted_results,
            'summary' => $summary_text,
            'troubleshooting_steps' => $this->getTroubleshootingSteps(),
            'overall_status' => $results['overall']['status']
        ];
    }

}
?>