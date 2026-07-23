<?php
class SpamDatabaseModel {
    private $mysqli;
    private $dnsbls = [
        'b.barracudacentral.org', 'bl.spamcop.net', 'blacklist.woody.ch', 'cbl.abuseat.org',
        'db.wpbl.info', 'dnsbl.cyberlogic.net', 'dnsbl.sorbs.net', 'drone.abuse.ch',
        'ips.backscatterer.org', 'pbl.spamhaus.org', 'sbl.spamhaus.org', 'spam.spamrats.com',
        'ubl.unsubscore.com', 'xbl.spamhaus.org', 'zen.spamhaus.org'
    ];
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function check($query) {
        @set_time_limit(120);
        $ip = $this->resolve($query);
        if (!$ip) return ['error' => 'Invalid IP or domain.'];
        $rev = implode('.', array_reverse(explode('.', $ip)));
        $res = [];
        foreach ($this->dnsbls as $bl) {
            $l = $rev . '.' . $bl;
            $listed = @checkdnsrr($l, "A");
            if (!$listed) {
                $h = @gethostbyname($l);
                if ($h !== $l) $listed = true;
            }
            $txt = null;
            if ($listed) {
                $t = @dns_get_record($l, DNS_TXT);
                $txt = $t[0]['txt'] ?? "Listed on $bl";
            }
            $res[] = ['dnsbl' => $bl, 'listed' => $listed, 'txt_record' => $txt];
        }
        $listed_count = count(array_filter($res, fn($r) => $r['listed']));
        return [
            'query' => $query,
            'resolved_ip' => $ip,
            'results' => $res,
            'listed_count' => $listed_count,
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => 'live_dnsbl_check'
        ];
    }
    private function resolve($q) {
        if (filter_var($q, FILTER_VALIDATE_IP)) return $q;
        $ip = gethostbyname($q);
        return ($ip && $ip !== $q) ? $ip : false;
    }
}