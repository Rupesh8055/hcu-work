<?php
require_once __DIR__ . '/../models/DnsLookupModel.php';
class DnsLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new DnsLookupModel($mysqli);
    }
    public function handleRequest($domain, $type) {
        $result = $this->model->lookup($domain, $type);
        return [
            'query' => ['tool' => 'dns-lookup', 'domain' => $domain, 'type' => $type],
            'response' => $result
        ];
    }
}
