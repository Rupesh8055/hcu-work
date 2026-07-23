<?php
class DnsReportModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getReport($domain, $type) {
        return [];
    }
}
