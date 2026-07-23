<?php
class IranFirewallTestModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function testUrl($url) {
        return [];
    }
}
