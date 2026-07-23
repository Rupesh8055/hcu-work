<?php
class UrlDecodeModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function decode($url) {
        return [];
    }

}
