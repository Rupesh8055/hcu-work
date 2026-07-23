<?php
class HttpHeadersModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function getHeaders($url) {
        return [];
    }
}
