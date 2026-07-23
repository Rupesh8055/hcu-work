<?php
class IpHistoryModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getHistory($ip) {
        return [];
    }
}
