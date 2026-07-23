<?php
class AbuseLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($query) {
        return [];
    }
}
