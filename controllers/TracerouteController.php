<?php
require_once __DIR__ . '/../models/TracerouteModel.php';
class TracerouteController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new TracerouteModel($mysqli);
    }
    public function handleRequest($host) {
        $result = $this->model->trace($host);
        return [
            'query' => ['tool' => 'traceroute', 'host' => $host],
            'response' => $result
        ];
    }

    public function addTrace($host, $result) {
        return $this->model->addTrace($host, $result);
    }
    public function updateTrace($host, $result) {
        return $this->model->updateTrace($host, $result);
    }
    public function deleteTrace($host) {
        return $this->model->deleteTrace($host);
    }
}
