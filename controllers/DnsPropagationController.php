<?php
require_once __DIR__ . '/../models/DnsPropagationModel.php';
class DnsPropagationController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new DnsPropagationModel($mysqli);
    }
    public function handleRequest($domain) {
        $result = $this->model->getPropagation($domain);
        return [
            'query' => ['tool' => 'dns-propagation', 'domain' => $domain],
            'response' => $result
        ];
    }

    public function addPropagation($domain, $result) {
        return $this->model->addPropagation($domain, $result);
    }
    public function updatePropagation($domain, $result) {
        return $this->model->updatePropagation($domain, $result);
    }
    public function deletePropagation($domain) {
        return $this->model->deletePropagation($domain);
    }
}
