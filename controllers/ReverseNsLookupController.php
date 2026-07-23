<?php
require_once __DIR__ . '/../models/ReverseNsLookupModel.php';
class ReverseNsLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new ReverseNsLookupModel($mysqli);
    }
    public function handleRequest($ns) {
        $result = $this->model->lookup($ns);
        return [
            'query' => ['tool' => 'reverse-ns-lookup', 'ns' => $ns],
            'response' => $result
        ];
    }

}
