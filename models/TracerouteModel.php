<?php
class TracerouteModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function trace($host) {
        return [];
    }

}
