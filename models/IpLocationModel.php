<?php
class IpLocationModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getLocation($ip) {
        return [];
    }
}
