<?php
class AsnLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($asn) {
        $asn = trim($asn);
        if (empty($asn)) return ['error' => 'ASN/IP is required.'];
        try {
            $ipQuery = false;
            $asnNumberOnly = null;

            if (filter_var($asn, FILTER_VALIDATE_IP)) {
                $ipQuery = true;
                $asnNumberOnly = $this->resolveIpToAsn($asn);
                if ($asnNumberOnly) {
                    $asnNumberOnly = preg_replace('/[^0-9]/', '', $asnNumberOnly);
                }
            } else {
                $asnNumberOnly = preg_replace('/[^0-9]/', '', $asn);
            }

            // 1. Primary: RDAP for rich entity/org data
            if (!empty($asnNumberOnly)) {
                $rdapResult = $this->lookupAsnFromRdap($asnNumberOnly);
                if ($rdapResult && !isset($rdapResult['error'])) {
                    return $rdapResult;
                }
            }

            // 2. Fallback: Local Database
            if ($ipQuery && filter_var($asn, FILTER_VALIDATE_IP)) {
                $ipLong = ip2long($asn);
                if ($ipLong !== false) {
                    $ipNum = sprintf('%u', $ipLong);
                    $stmt = $this->mysqli->prepare("SELECT asn, isp_org, country_code, registry FROM ip_ranges WHERE ? BETWEEN start_ip_num AND end_ip_num LIMIT 1");
                    if ($stmt) {
                        $stmt->bind_param('s', $ipNum);
                        $stmt->execute();
                        $res = $stmt->get_result();
                        if ($row = $res->fetch_assoc()) {
                            if (!empty($row['asn'])) {
                                $stmt->close();
                                return [
                                    'status' => 'success',
                                    'asn' => 'AS' . $row['asn'],
                                    'name' => $row['isp_org'],
                                    'country' => $row['country_code'],
                                    'registry' => $row['registry'],
                                    'allocated' => '',
                                    'source' => 'local_database',
                                    'historical_domains' => $this->getHistoricalDomains($row['asn'])
                                ];
                            }
                        }
                        $stmt->close();
                    }
                }
            } else if (!empty($asnNumberOnly)) {
                $stmt = $this->mysqli->prepare("SELECT asn, isp_org, country_code, registry FROM ip_ranges WHERE asn = ? LIMIT 1");
                if ($stmt) {
                    $stmt->bind_param('i', $asnNumberOnly);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    if ($row = $res->fetch_assoc()) {
                        $stmt->close();
                        return [
                            'status' => 'success',
                            'asn' => 'AS' . $row['asn'],
                            'name' => $row['isp_org'],
                            'country' => $row['country_code'],
                            'registry' => $row['registry'],
                            'allocated' => '',
                            'source' => 'local_database',
                            'historical_domains' => $this->getHistoricalDomains($row['asn'])
                        ];
                    }
                    $stmt->close();
                }
            }

            // 3. Fallback: WHOIS TCP
            if (!empty($asnNumberOnly)) {
                return $this->lookupAsnFromWhois($asnNumberOnly);
            }

            return ['error' => 'Could not determine ASN.'];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while looking up ASN information.'];
        }
    }
    private function resolveIpToAsn($ip) {
        // Try RDAP for IP first
        $ch = curl_init("https://rdap.org/ip/" . $ip);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res) {
            $data = json_decode($res, true);
            // IP RDAP doesn't always give ASN directly, often we have to look at the CIDR or we can just fallback to Cymru
        }

        $response = $this->whoisTcp("-v " . $ip, 'whois.cymru.com');
        if ($response) {
            foreach (explode("\n", $response) as $line) {
                if (strpos($line, '|') !== false && stripos($line, 'AS Name') === false) {
                    $parts = explode('|', $line);
                    if (isset($parts[0])) return trim($parts[0]);
                }
            }
        }
        return null;
    }

    private function lookupAsnFromWhois($asnNumber) {
        // Try RDAP first
        $rdapResult = $this->lookupAsnFromRdap($asnNumber);
        if ($rdapResult && !isset($rdapResult['error'])) {
            return $rdapResult;
        }

        $whoisRaw = $this->whoisTcp('-v AS' . $asnNumber, 'whois.cymru.com');
        if (!$whoisRaw || strpos($whoisRaw, '|') === false) {
            $whoisRaw = $this->whoisTcp('AS' . $asnNumber, 'whois.radb.net');
        }
        if ($whoisRaw) return $this->parseAsnWhois($whoisRaw, $asnNumber);
        return ['error' => 'Could not retrieve ASN data.'];
    }

    private function lookupAsnFromRdap($asnNumber) {
        $endpoints = [
            "https://rdap.arin.net/registry/autnum/" . $asnNumber,
            "https://rdap.db.ripe.net/autnum/" . $asnNumber,
            "https://rdap.apnic.net/autnum/" . $asnNumber,
            "https://rdap.lacnic.net/rdap/autnum/" . $asnNumber,
            "https://rdap.afrinic.net/rdap/autnum/" . $asnNumber,
            "https://rdap.org/autnum/" . $asnNumber
        ];

        $data = null;
        foreach ($endpoints as $url) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 6);
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/rdap+json, application/json']);
            $res = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300 && $res) {
                $decoded = json_decode($res, true);
                if ($decoded && (isset($decoded['handle']) || isset($decoded['name']) || isset($decoded['startAutnum']))) {
                    $data = $decoded;
                    break;
                }
            }
        }

        if (!$data) return ['error' => 'RDAP lookup failed across registry endpoints.'];

        $asnHandle = $data['handle'] ?? ('AS' . $asnNumber);
        $asnName = $data['name'] ?? '';
        
        $asRegDate = '';
        $asUpdatedDate = '';
        if (!empty($data['events'])) {
            foreach ($data['events'] as $ev) {
                $act = strtolower($ev['eventAction'] ?? '');
                if ($act === 'registration') $asRegDate = substr($ev['eventDate'] ?? '', 0, 10);
                if ($act === 'last changed') $asUpdatedDate = substr($ev['eventDate'] ?? '', 0, 10);
            }
        }
        
        $asRef = '';
        if (!empty($data['links'])) {
            foreach ($data['links'] as $link) {
                if (($link['rel'] ?? '') === 'self') {
                    $asRef = $link['href'] ?? '';
                    break;
                }
            }
        }
        
        $parsedEntities = [];
        
        $flattenEntities = function($entityList) use (&$flattenEntities, &$parsedEntities) {
            foreach ($entityList as $ent) {
                $roles = $ent['roles'] ?? [];
                $handle = $ent['handle'] ?? '';
                $ref = '';
                if (!empty($ent['links'])) {
                    foreach ($ent['links'] as $link) {
                        if (($link['rel'] ?? '') === 'self') {
                            $ref = $link['href'] ?? '';
                            break;
                        }
                    }
                }
                
                $regDate = '';
                $updatedDate = '';
                if (!empty($ent['events'])) {
                    foreach ($ent['events'] as $ev) {
                        $act = strtolower($ev['eventAction'] ?? '');
                        if ($act === 'registration') $regDate = substr($ev['eventDate'] ?? '', 0, 10);
                        if ($act === 'last changed') $updatedDate = substr($ev['eventDate'] ?? '', 0, 10);
                    }
                }
                
                $comment = '';
                if (!empty($ent['remarks'])) {
                    $comments = [];
                    foreach ($ent['remarks'] as $rem) {
                        if (!empty($rem['description'])) {
                            $comments[] = implode(" ", array_filter((array)$rem['description']));
                        }
                    }
                    $comment = trim(implode(" | ", array_filter($comments)));
                }
                
                $fn = '';
                $email = '';
                $phone = '';
                $address = '';
                $city = '';
                $stateProv = '';
                $postalCode = '';
                $country = '';
                
                if (isset($ent['vcardArray'][1])) {
                    foreach ($ent['vcardArray'][1] as $vcard) {
                        $prop = $vcard[0] ?? '';
                        $val = $vcard[3] ?? '';
                        if ($prop === 'fn') {
                            $fn = is_string($val) ? $val : '';
                        } elseif ($prop === 'email') {
                            $email = is_string($val) ? $val : '';
                        } elseif ($prop === 'tel') {
                            $phone = is_string($val) ? $val : '';
                        } elseif ($prop === 'adr') {
                            $params = $vcard[1] ?? [];
                            if (isset($params['label'])) {
                                $lines = array_values(array_filter(array_map('trim', explode("\n", $params['label']))));
                                if (count($lines) >= 1) $address = $lines[0];
                                if (count($lines) >= 2) $city = $lines[1];
                                if (count($lines) >= 3) $stateProv = $lines[2];
                                if (count($lines) >= 4) $postalCode = $lines[3];
                                if (count($lines) >= 5) $country = $lines[4];
                            } elseif (is_array($val)) {
                                $parts = array_values(array_filter($val));
                                if (count($parts) >= 1) $address = $parts[0];
                                if (count($parts) >= 2) $city = $parts[1];
                                if (count($parts) >= 3) $stateProv = $parts[2];
                                if (count($parts) >= 4) $postalCode = $parts[3];
                                if (count($parts) >= 5) $country = $parts[count($parts)-1];
                            }
                        }
                    }
                }
                
                $entObj = [
                    'handle' => $handle,
                    'name' => $fn ?: $handle,
                    'roles' => $roles,
                    'address' => $address,
                    'city' => $city,
                    'state_prov' => $stateProv,
                    'postal_code' => $postalCode,
                    'country' => $country,
                    'email' => $email,
                    'phone' => $phone,
                    'reg_date' => $regDate,
                    'updated' => $updatedDate,
                    'comment' => $comment,
                    'ref' => $ref
                ];
                
                $parsedEntities[] = $entObj;
                
                if (!empty($ent['entities'])) {
                    $flattenEntities($ent['entities']);
                }
            }
        };
        
        if (!empty($data['entities'])) {
            $flattenEntities($data['entities']);
        }
        
        return [
            'status' => 'success',
            'asn' => $asnHandle,
            'as_number' => $asnNumber,
            'as_name' => $asnName,
            'as_handle' => $asnHandle,
            'reg_date' => $asRegDate,
            'updated' => $asUpdatedDate,
            'ref' => $asRef,
            'registry' => $data['port43'] ?? 'RDAP',
            'entities' => $parsedEntities,
            'raw_rdap' => json_encode($data, JSON_PRETTY_PRINT),
            'historical_domains' => $this->getHistoricalDomains($asnNumber)
        ];
    }

    private function getHistoricalDomains($asnNumber) {
        if (!$this->mysqli || empty($asnNumber)) return [];
        // Uses INET_ATON for IPv4 only. In a large db this join might be slow, but it's limited to 25.
        $stmt = $this->mysqli->prepare("
            SELECT DISTINCT d.domain 
            FROM ip_domain_mapping d 
            JOIN ip_ranges r ON INET_ATON(d.ip) BETWEEN r.start_ip_num AND r.end_ip_num 
            WHERE r.asn = ? 
            LIMIT 25
        ");
        if (!$stmt) return [];
        $stmt->bind_param('i', $asnNumber);
        $stmt->execute();
        $res = $stmt->get_result();
        $domains = [];
        while ($row = $res->fetch_assoc()) {
            if ($row['domain'] !== 'unknown') {
                $domains[] = $row['domain'];
            }
        }
        $stmt->close();
        return $domains;
    }

    private function whoisTcp($query, $server) {
        $fp = @fsockopen($server, 43, $errno, $errstr, 5);
        if (!$fp) return null;
        stream_set_timeout($fp, 5);
        fwrite($fp, $query . "\r\n");
        $response = "";
        while (!feof($fp)) {
            $line = fgets($fp, 1024);
            if ($line === false) break;
            $response .= $line;
        }
        fclose($fp);
        return $response;
    }

    private function parseAsnWhois($raw, $asnNumber) {
        if (strpos($raw, '|') !== false) {
            foreach (explode("\n", $raw) as $line) {
                if (strpos($line, '|') !== false && stripos($line, 'AS Name') === false) {
                    $parts = array_map('trim', explode('|', $line));
                    if (isset($parts[0]) && (strcasecmp($parts[0], $asnNumber) === 0 || strcasecmp($parts[0], 'AS'.$asnNumber) === 0)) {
                        return [
                            'status' => 'success',
                            'asn' => 'AS' . $asnNumber,
                            'name' => $parts[4] ?? 'Unknown',
                            'country' => $parts[1] ?? '',
                            'registry' => $parts[2] ?? '',
                            'allocated' => $parts[3] ?? '',
                            'source' => 'cymru_whois',
                            'raw' => trim($raw)
                        ];
                    }
                }
            }
        }
        return ['error' => 'No ASN information found for this query.'];
    }
}