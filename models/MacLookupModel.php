<?php
class MacLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookupMac($mac) {
        return [];
    }
}
