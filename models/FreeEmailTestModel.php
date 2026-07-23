<?php
class FreeEmailTestModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function testEmail($email) {
        return [];
    }
}
