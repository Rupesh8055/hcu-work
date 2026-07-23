<?php
require_once __DIR__ . '/../models/ReverseIpLookupModel.php';
class ReverseIpLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new ReverseIpLookupModel($mysqli);
    }
    public function handleRequest($ip) {
        $result = $this->model->lookup($ip);
        return [
            'query' => ['tool' => 'reverse-ip-lookup', 'ip' => $ip],
            'response' => $result
        ];
    }

}
