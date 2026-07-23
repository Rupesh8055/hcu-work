<?php
require_once __DIR__ . '/../models/AsnLookupModel.php';
class AsnLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new AsnLookupModel($mysqli);
    }
    public function handleRequest($query) {
        $result = $this->model->getAsnInfo($query);
        return [
            'query' => ['tool' => 'asn-lookup', 'query' => $query],
            'response' => $result
        ];
    }
    public function addAsn($asn, $info) {
        return $this->model->addAsn($asn, $info);
    }
    public function updateAsn($asn, $info) {
        return $this->model->updateAsn($asn, $info);
    }
    public function deleteAsn($asn) {
        return $this->model->deleteAsn($asn);
    }
}
