<?php
class ReverseNsLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($ns) {
        return [];
    }
}
