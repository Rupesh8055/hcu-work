<?php
require_once __DIR__ . '/../models/HttpHeadersModel.php';
class HttpHeadersController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new HttpHeadersModel($mysqli);
    }
    public function handleRequest($url) {
        $result = $this->model->getHeaders($url);
        return [
            'query' => ['tool' => 'http-headers', 'url' => $url],
            'response' => $result
        ];
    }

    public function addHeaders($url, $result) {
        return $this->model->addHeaders($url, $result);
    }
    public function updateHeaders($url, $result) {
        return $this->model->updateHeaders($url, $result);
    }
    public function deleteHeaders($url) {
        return $this->model->deleteHeaders($url);
    }
}
