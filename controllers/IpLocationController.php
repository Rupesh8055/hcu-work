<?php
require_once __DIR__ . '/../models/IpLocationModel.php';
class IpLocationController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new IpLocationModel($mysqli);
    }
    public function handleRequest($ip) {
        $result = $this->model->getLocation($ip);
        return [
            'query' => ['tool' => 'ip-location', 'ip' => $ip],
            'response' => $result
        ];
    }

    public function addLocation($ip, $result) {
        return $this->model->addLocation($ip, $result);
    }
    public function updateLocation($ip, $result) {
        return $this->model->updateLocation($ip, $result);
    }
    public function deleteLocation($ip) {
        return $this->model->deleteLocation($ip);
    }
}
