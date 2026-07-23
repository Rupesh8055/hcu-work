<?php
require_once __DIR__ . '/../models/ReverseDnsModel.php';

class ReverseDnsController {
    private $model;

    public function __construct($mysqli) {
        $this->model = new ReverseDnsModel($mysqli);
    }

    public function handleRequest($ip) {
        $result = $this->model->reverseLookup($ip);
        return [
            'query' => ['tool' => 'reverse-dns', 'ip' => $ip],
            'response' => $result
        ];
    }
}
