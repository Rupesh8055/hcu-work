<?php
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class DnsPropagationModel {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    private function getResolvers() {
        $resolvers = [];
        $res = $this->mysqli->query("SELECT ip, name, location as loc, latitude as lat, longitude as lon FROM dns_resolvers WHERE status = 'active'");
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $resolvers[] = $row;
            }
        }
        return $resolvers;
    }

    public function check($domain, $recordType = 'A') {
        if (empty($domain)) return ['error' => 'Domain is required'];
        $domain = strtolower(trim($domain));
        $recordType = strtoupper($recordType);

        $results = [];
        $uniqueValues = [];
        $ttls = [];
        $totalResponded = 0;

        $resolvers = $this->getResolvers();
        foreach ($resolvers as $res) {
            $val = $this->queryResolver($res['ip'], $domain, $recordType);
            if ($val !== false) {
                $totalResponded++;
                $flatVals = array_column($val, 'value');
                $results[] = [
                    'resolver' => $res['name'],
                    'ip' => $res['ip'],
                    'location' => $res['loc'],
                    'lat' => $res['lat'],
                    'lon' => $res['lon'],
                    'value' => $flatVals,
                    'records' => $val,
                    'status' => 'PASS'
                ];
                if (!empty($val)) {
                    foreach ($val as $v) {
                        $uniqueValues[] = $v['value'];
                        $ttls[] = $v['ttl'];
                    }
                }
            } else {
                $results[] = [
                    'resolver' => $res['name'],
                    'ip' => $res['ip'],
                    'location' => $res['loc'],
                    'lat' => $res['lat'],
                    'lon' => $res['lon'],
                    'value' => [],
                    'records' => [],
                    'status' => 'FAIL'
                ];
            }
        }

        $uniqueCount = count(array_unique($uniqueValues));
        $consistencyScore = 0;
        if ($totalResponded > 0 && !empty($uniqueValues)) {
            $valueCounts = array_count_values($uniqueValues);
            $maxCount = max($valueCounts);
            $consistencyScore = round(($maxCount / $totalResponded) * 100, 2);
        }

        $status = 'Inconsistent';
        if ($totalResponded > 0) {
            if ($uniqueCount === 1) $status = 'Likely Propagated';
            elseif ($uniqueCount > 1) $status = 'Possibly Inconsistent';
            elseif (empty($uniqueValues)) $status = 'Not Found';
        } else {
            $status = 'Network Error';
        }

        // Store NS records if found
        if ($recordType === 'NS' && !empty($uniqueValues)) {
            DatabaseManager::storeNameservers($this->mysqli, $domain, array_unique($uniqueValues));
        }

        return [
            'domain' => $domain,
            'type' => $recordType,
            'status' => $status,
            'unique_count' => $uniqueCount,
            'consistency_score' => $consistencyScore . '%',
            'average_ttl' => empty($ttls) ? 0 : round(array_sum($ttls) / count($ttls), 2),
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    private function queryResolver($resolverIp, $domain, $type) {
        // Direct UDP socket query (port 53)
        $id = rand(10000, 65535);
        $header = pack('n6', $id, 0x0100, 1, 0, 0, 0);
        
        $qname = '';
        foreach (explode('.', $domain) as $part) {
            $qname .= chr(strlen($part)) . $part;
        }
        $qname .= "\x00";
        
        $typeMap = ['A' => 1, 'NS' => 2, 'CNAME' => 5, 'SOA' => 6, 'PTR' => 12, 'MX' => 15, 'TXT' => 16, 'AAAA' => 28];
        $typeCode = $typeMap[$type] ?? 1;
        $question = $qname . pack('n2', $typeCode, 1);
        
        $packet = $header . $question;
        
        $fp = @fsockopen("udp://$resolverIp", 53, $errno, $errstr, 1);
        if (!$fp) return false;
        
        stream_set_timeout($fp, 1);
        fwrite($fp, $packet);
        $response = fread($fp, 1024);
        fclose($fp);
        
        if (!$response) return false;
        return $this->parseDnsResponse($response);
    }

    private function parseDnsResponse($buf) {
        if (strlen($buf) < 12) return [];
        $header = unpack('n6', substr($buf, 0, 12));
        $answersCount = $header[4];
        if ($answersCount == 0) return [];
        
        $offset = 12;
        // Skip Question Section
        while ($offset < strlen($buf)) {
            $len = ord($buf[$offset]);
            if ($len == 0) { $offset += 5; break; }
            if (($len & 0xC0) == 0xC0) { $offset += 6; break; }
            $offset += $len + 1;
        }
        
        $records = [];
        for ($i = 0; $i < $answersCount; $i++) {
            if ($offset >= strlen($buf)) break;
            $this->skipName($buf, $offset);
            if ($offset + 10 > strlen($buf)) break;
            $meta = unpack('n2type_class/Nttl/nrdlength', substr($buf, $offset, 10));
            $offset += 10;
            $rdlength = $meta['rdlength'];
            $data = substr($buf, $offset, $rdlength);
            $offset += $rdlength;
            
            $type = $meta['type_class1'];
            if ($type == 1 && $rdlength == 4) { // A
                $valStr = implode('.', unpack('C4', $data));
                $records[] = ['value' => $valStr, 'ttl' => $meta['ttl']];
            } elseif ($type == 28 && $rdlength == 16) { // AAAA
                $valStr = implode(':', str_split(bin2hex($data), 4));
                $records[] = ['value' => $valStr, 'ttl' => $meta['ttl']];
            } elseif ($type == 2 || $type == 5) { // NS or CNAME
                $tmpOffset = $offset - $rdlength;
                $valStr = $this->readName($buf, $tmpOffset);
                $records[] = ['value' => $valStr, 'ttl' => $meta['ttl']];
            }
        }
        return $records;
    }

    private function skipName($buf, &$offset) {
        while (true) {
            $len = ord($buf[$offset]);
            if ($len == 0) { $offset++; break; }
            if (($len & 0xC0) == 0xC0) { $offset += 2; break; }
            $offset += $len + 1;
        }
    }

    private function readName($buf, &$offset) {
        $name = '';
        while (true) {
            if ($offset >= strlen($buf)) break;
            $len = ord($buf[$offset]);
            if ($len == 0) { $offset++; break; }
            if (($len & 0xC0) == 0xC0) {
                if ($offset + 2 > strlen($buf)) break;
                $ptr = unpack('n', substr($buf, $offset, 2))[1] & 0x3FFF;
                $offset += 2;
                $tmp = $ptr;
                return $name . $this->readName($buf, $tmp);
            }
            $offset++;
            if ($offset + $len > strlen($buf)) break;
            $name .= substr($buf, $offset, $len) . '.';
            $offset += $len;
        }
        return rtrim($name, '.');
    }
}