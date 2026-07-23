<?php
require_once __DIR__ . '/../models/WhoisLookupModel.php';
class WhoisLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new WhoisLookupModel($mysqli);
    }
    public function handleRequest($domain) {
        $result = $this->model->lookup($domain);
        return [
            'query' => ['tool' => 'whois-lookup', 'domain' => $domain],
            'response' => $result
        ];
    }

}
