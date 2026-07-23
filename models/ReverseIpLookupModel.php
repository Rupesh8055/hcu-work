<?php
class ReverseIpLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($ip) {
        return [];
    }
}
