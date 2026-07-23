<?php
class ReverseWhoisLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookup($searchTerm, $searchType) {
        return [];
    }
}
