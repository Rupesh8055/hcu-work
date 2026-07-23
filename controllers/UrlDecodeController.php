<?php
require_once __DIR__ . '/../models/UrlDecodeModel.php';
class UrlDecodeController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new UrlDecodeModel($mysqli);
    }
    public function handleRequest($url) {
        $result = $this->model->decode($url);
        return [
            'query' => ['tool' => 'url-decode', 'url' => $url],
            'response' => $result
        ];
    }

}
