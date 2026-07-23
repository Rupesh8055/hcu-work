<?php
class DnssecTestModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getDnssec($domain) {
        return [];
    }
}
