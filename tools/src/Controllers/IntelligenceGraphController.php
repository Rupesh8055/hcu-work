<?php
require_once __DIR__ . '/../Models/IntelligenceGraphModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class IntelligenceGraphController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($query) {
        if (empty($query)) return ['error' => 'Domain or IP address is required.'];
        
        $query = strtolower(trim($query));
        
        if (!filter_var($query, FILTER_VALIDATE_IP) && !preg_match('/^(?!:\/\/)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/', $query)) {
            return ['error' => 'Invalid target format. Please provide a valid IP address or domain name.'];
        }

        DatabaseManager::logRequest($this->mysqli, 'intelligence-graph', $query);

        $model = new IntelligenceGraphModel($this->mysqli);
        $data = $model->buildGraph($query);

        if (isset($data['error'])) {
            return ['error' => 'System error: ' . $data['error']];
        }

        return ['response' => $data, 'cached' => false];
    }
}
