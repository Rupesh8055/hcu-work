<?php
require_once __DIR__ . '/../models/IpHistoryModel.php';
class IpHistoryController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new IpHistoryModel($mysqli);
    }
    public function handleRequest($query) {
        $result = $this->model->getHistory($query);
        return [
            'query' => ['tool' => 'ip-history', 'query' => $query],
            'response' => $result
        ];
    }
    public function addHistory($ip, $result) {
        return $this->model->addHistory($ip, $result);
    }
    public function updateHistory($ip, $result) {
        return $this->model->updateHistory($ip, $result);
    }
    public function deleteHistory($ip) {
        return $this->model->deleteHistory($ip);
    }
}
