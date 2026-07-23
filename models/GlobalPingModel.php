<?php
class GlobalPingModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function pingHost($host) {
        return [];
    }
}
