<?php
require_once __DIR__ . '/../models/AbuseLookupModel.php';
class AbuseLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new AbuseLookupModel($mysqli);
    }
    public function handleRequest($query) {
        $result = $this->model->lookup($query);
        return [
            'query' => ['tool' => 'abuse-lookup', 'query' => $query],
            'response' => $result
        ];
    }

}
