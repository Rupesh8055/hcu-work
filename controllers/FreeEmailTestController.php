<?php
require_once __DIR__ . '/../models/FreeEmailTestModel.php';
class FreeEmailTestController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new FreeEmailTestModel($mysqli);
    }
    public function handleRequest($email) {
        $result = $this->model->testEmail($email);
        return [
            'query' => ['tool' => 'free-email-test', 'email' => $email],
            'response' => $result
        ];
    }

    public function addTest($email, $result) {
        return $this->model->addTest($email, $result);
    }
    public function updateTest($email, $result) {
        return $this->model->updateTest($email, $result);
    }
    public function deleteTest($email) {
        return $this->model->deleteTest($email);
    }
}
