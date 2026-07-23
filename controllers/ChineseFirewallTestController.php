<?php
require_once __DIR__ . '/../models/ChineseFirewallTestModel.php';
class ChineseFirewallTestController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new ChineseFirewallTestModel($mysqli);
    }
    public function handleRequest($url) {
        $result = $this->model->testUrl($url);
        return [
            'query' => ['tool' => 'chinese-firewall-test', 'url' => $url],
            'response' => $result
        ];
    }

    public function addTest($url, $result) {
        return $this->model->addTest($url, $result);
    }
    public function updateTest($url, $result) {
        return $this->model->updateTest($url, $result);
    }
    public function deleteTest($url) {
        return $this->model->deleteTest($url);
    }
}
