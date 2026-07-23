<?php
require_once __DIR__ . '/../models/DnsReportModel.php';
class DnsReportController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new DnsReportModel($mysqli);
    }
    public function handleRequest($domain) {
        $result = $this->model->getReport($domain, 'ALL');
        return [
            'query' => ['tool' => 'dns-report', 'domain' => $domain],
            'response' => $result
        ];
    }
    public function addReport($domain, $type, $result) {
        return $this->model->addReport($domain, $type, $result);
    }
    public function updateReport($domain, $type, $result) {
        return $this->model->updateReport($domain, $type, $result);
    }
    public function deleteReport($domain, $type) {
        return $this->model->deleteReport($domain, $type);
    }
}
