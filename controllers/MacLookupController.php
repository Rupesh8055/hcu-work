<?php
require_once __DIR__ . '/../models/MacLookupModel.php';
class MacLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new MacLookupModel($mysqli);
    }
    public function handleRequest($mac) {
        $result = $this->model->lookupMac($mac);
        return [
            'query' => ['tool' => 'mac-lookup', 'mac' => $mac],
            'response' => $result
        ];
    }
    public function addMac($mac, $result) {
        return $this->model->addMac($mac, $result);
    }
    public function updateMac($mac, $result) {
        return $this->model->updateMac($mac, $result);
    }
    public function deleteMac($mac) {
        return $this->model->deleteMac($mac);
    }
}
