<?php
class DnsLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($domain, $type) {
        return [];
    }
}
