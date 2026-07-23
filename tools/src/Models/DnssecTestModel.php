<?php
class DnssecTestModel {
    private $mysqli;
    private $dnsServer = '8.8.8.8';
    private $algorithms = [1 => 'RSA/MD5', 2 => 'Diffie-Hellman', 3 => 'DSA/SHA1', 5 => 'RSA/SHA-1', 6 => 'DSA-NSEC3-SHA1', 7 => 'RSASHA1-NSEC3-SHA1', 8 => 'RSA/SHA-256', 10 => 'RSA/SHA-512', 13 => 'ECDSA P-256 with SHA-256', 14 => 'ECDSA P-384 with SHA-384', 15 => 'Ed25519', 16 => 'Ed448'];
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function test($domain) {
        $domain = trim($domain, " \t\n\r\0\x0B.");
        if (empty($domain)) return ['error' => 'Domain is required.'];
        try {
            return $this->checkDnssec($domain);
        } catch (Throwable $e) {
            return ['error' => 'DNSSEC validation error.'];
        }
    }
    private function checkDnssec($domain) {
        $types = [6 => 'SOA', 48 => 'DNSKEY', 43 => 'DS', 1 => 'A'];
        $allRRs = [];
        foreach ($types as $typeId => $typeName) {
            $response = $this->queryNative($domain, $typeId);
            if ($response) $allRRs = array_merge($allRRs, $response);
        }
        $sigs = []; $foundDnskey = false; $foundDs = false;
        foreach ($allRRs as $rr) {
            if ($rr['type'] == 46) {
                $p = $this->parseRrsig($rr['data']);
                if ($p && strtolower(trim($p['signer'], '.')) === strtolower($domain)) {
                    $sigs[$p['type_covered'] . '|' . $p['key_tag']] = $p;
                }
            }
            if ($rr['type'] == 48 && strtolower(trim($rr['name'], '.')) === strtolower($domain)) $foundDnskey = true;
            if ($rr['type'] == 43) $foundDs = true;
        }
        $sigsArr = array_values($sigs);
        $tests = [
            'dnssec_exists' => ['status' => ($foundDnskey || !empty($sigsArr)) ? 'passed' : 'failed', 'message' => 'DNSSEC records found'],
            'dnssec_valid' => ['status' => !empty($sigsArr) ? 'passed' : 'failed', 'message' => 'DNSSEC signatures found'],
            'dnssec_chain' => ['status' => $foundDs ? 'passed' : 'failed', 'message' => 'Chain of Trust (DS)']
        ];
        $passed = count(array_filter($tests, fn($t) => $t['status'] === 'passed'));
        $status = ($passed === 3) ? 'secure' : ($passed > 0 ? 'partially_secure' : 'insecure');
        return ['status' => $status, 'domain' => $domain, 'tests' => $tests, 'signatures' => $sigsArr, 'timestamp' => date('Y-m-d H:i:s')];
    }
    private function queryNative($domain, $type) {
        $header = pack('n6', rand(1, 65535), 0x0100, 1, 0, 0, 1);
        $qname = '';
        foreach (explode('.', $domain) as $part) $qname .= chr(strlen($part)) . $part;
        $qname .= "\x00";
        $packet = $header . $qname . pack('n2', $type, 1) . "\x00" . pack('n', 41) . pack('n', 4096) . "\x00\x00" . pack('n', 0x8000) . pack('n', 0);
        $sock = @fsockopen("udp://" . $this->dnsServer, 53, $errno, $errstr, 2);
        if (!$sock) return [];
        fwrite($sock, $packet);
        stream_set_timeout($sock, 2);
        $res = fread($sock, 4096);
        fclose($sock);
        return $res ? $this->parseResponse($res) : [];
    }
    private function parseResponse($buf) {
        $h = unpack('n6', substr($buf, 0, 12));
        $offset = 12;
        for ($i = 0; $i < $h[3]; $i++) { $this->skipName($buf, $offset); $offset += 4; }
        $recs = [];
        for ($i = 0; $i < ($h[4] + $h[5] + $h[6]); $i++) {
            $name = $this->readName($buf, $offset);
            $m = unpack('n2type_class/Nttl/nrdlength', substr($buf, $offset, 10));
            $offset += 10;
            $data = substr($buf, $offset, $m['rdlength']);
            $offset += $m['rdlength'];
            $recs[] = ['name' => $name, 'type' => $m['type_class1'], 'data' => $data];
        }
        return $recs;
    }
    private function readName($buf, &$offset) {
        $name = '';
        while (true) {
            $len = ord($buf[$offset]);
            if ($len == 0) { $offset++; break; }
            if (($len & 0xC0) == 0xC0) {
                $ptr = unpack('n', substr($buf, $offset, 2))[1] & 0x3FFF;
                $offset += 2; $tmp = $ptr;
                return $name . $this->readName($buf, $tmp);
            }
            $offset++; $name .= substr($buf, $offset, $len) . '.'; $offset += $len;
        }
        return rtrim($name, '.');
    }
    private function skipName($buf, &$offset) {
        while (true) {
            $len = ord($buf[$offset]);
            if ($len == 0) { $offset++; break; }
            if (($len & 0xC0) == 0xC0) { $offset += 2; break; }
            $offset += $len + 1;
        }
    }
    private function parseRrsig($data) {
        if (strlen($data) < 18) return null;
        $m = unpack('ncovered/Calgo/Clabels/Nttl/Nexp/Nincep/ntag', substr($data, 0, 18));
        $off = 18; $signer = $this->readName($data, $off);
        $types = [1 => 'A', 2 => 'NS', 5 => 'CNAME', 6 => 'SOA', 15 => 'MX', 16 => 'TXT', 28 => 'AAAA', 46 => 'RRSIG', 48 => 'DNSKEY', 43 => 'DS'];
        return [
            'type_covered' => $types[$m['covered']] ?? "Type " . $m['covered'],
            'algorithm' => $m['algo'],
            'algorithm_name' => $this->algorithms[$m['algo']] ?? 'Unknown',
            'signer' => $signer,
            'key_tag' => $m['tag']
        ];
    }
}