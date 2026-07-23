<?php
require_once __DIR__ . '/../models/SpamDatabaseModel.php';

class SpamDatabaseController {
    private $mysqli;
    private $model;
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new SpamDatabaseModel($mysqli);
    }
    
    public function handleRequest($query) {
        try {
            if (empty($query)) {
                return [
                    'query' => ['tool' => 'spam-database', 'query' => ''],
                    'response' => ['error' => 'Query parameter is required.']
                ];
            }
            $sanitizedQuery = SecurityUtils::sanitizeInput(trim($query), 'text', 255);
            if (!$sanitizedQuery) {
                return [
                    'query' => ['tool' => 'spam-database', 'query' => $query],
                    'response' => ['error' => 'Invalid query format provided.']
                ];
            }
            if (strlen($sanitizedQuery) > 255) {
                return [
                    'query' => ['tool' => 'spam-database', 'query' => $sanitizedQuery],
                    'response' => ['error' => 'Query too long. Please provide a valid IP address or domain.']
                ];
            }
            $results = $this->model->checkDnsbls($sanitizedQuery);
            return [
                'query' => ['tool' => 'spam-database', 'query' => $sanitizedQuery],
                'response' => $results
            ];
        } catch (Exception $e) {
            return [
                'query' => ['tool' => 'spam-database', 'query' => $query ?? ''],
                'response' => ['error' => 'An internal error occurred: ' . $e->getMessage()]
            ];
        }
    }
}
?>