<?php
class NameserverSitesModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getSites($nameserver) {
        return [];
    }
}
