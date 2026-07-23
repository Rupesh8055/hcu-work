<?php
require_once __DIR__ . '/../models/GlobalPingModel.php';
class GlobalPingController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new GlobalPingModel($mysqli);
    }
    public function handleRequest($host) {
        $result = $this->model->pingHost($host);
        return [
            'query' => ['tool' => 'global-ping', 'host' => $host],
            'response' => $result
        ];
    }

    public function addPing($host, $result) {
        return $this->model->addPing($host, $result);
    }
    public function updatePing($host, $result) {
        return $this->model->updatePing($host, $result);
    }
    public function deletePing($host) {
        return $this->model->deletePing($host);
    }
}
