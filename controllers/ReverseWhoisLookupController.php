<?php
require_once __DIR__ . '/../models/ReverseWhoisLookupModel.php';
class ReverseWhoisLookupController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new ReverseWhoisLookupModel($mysqli);
    }
    public function handleRequest($searchTerm, $searchType) {
        $result = $this->model->lookup($searchTerm, $searchType);
        return [
            'query' => ['tool' => 'reverse-whois-lookup', 'searchTerm' => $searchTerm, 'searchType' => $searchType],
            'response' => $result
        ];
    }

}
