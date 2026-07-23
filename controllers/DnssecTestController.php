<?php
require_once __DIR__ . '/../models/DnssecTestModel.php';
class DnssecTestController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new DnssecTestModel($mysqli);
    }
    public function handleRequest($domain) {
        $result = $this->model->getDnssec($domain);
        return [
            'query' => ['tool' => 'dnssec-test', 'domain' => $domain],
            'response' => $result
        ];
    }

    public function addDnssec($domain, $result) {
        return $this->model->addDnssec($domain, $result);
    }
    public function updateDnssec($domain, $result) {
        return $this->model->updateDnssec($domain, $result);
    }
    public function deleteDnssec($domain) {
        return $this->model->deleteDnssec($domain);
    }
}
