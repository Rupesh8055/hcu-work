<?php
class AsnLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getAsnInfo($asn) {
        return [];
    }
}
