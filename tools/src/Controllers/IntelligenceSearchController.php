<?php
require_once __DIR__ . '/../Models/IntelligenceSearchModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

class IntelligenceSearchController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handleRequest($query) {
        if (empty($query)) return ['error' => 'Search term is required.'];
        
        $query = strtolower(trim($query));

        if (strlen($query) < 2) return ['error' => 'Search term must be at least 2 characters long.'];
        if (strlen($query) > 100) return ['error' => 'Search term must be less than 100 characters.'];
        
        // Ensure there is at least one alphanumeric character
        if (!preg_match('/[a-z0-9]/i', $query)) {
            return ['error' => 'Search term must contain alphanumeric characters.'];
        }

        DatabaseManager::logRequest($this->mysqli, 'intelligence-search', $query);

        // Check database cache first
        $cache = DatabaseManager::checkCache($this->mysqli, 'intelligence-search', $query);
        if ($cache['status'] === 'hit') {
            return ['response' => $cache['data'], 'cached' => true];
        }

        $model = new IntelligenceSearchModel($this->mysqli);
        $data = $model->search($query);

        if (isset($data['error'])) {
            return ['error' => 'System error during footprint search: ' . $data['error']];
        }

        // Cache the final correlated relationships
        DatabaseManager::storeResult($this->mysqli, 'intelligence-search', $query, $data);

        return ['response' => $data, 'cached' => false];
    }
}
