<?php
require_once __DIR__ . '/../models/PortScannerModel.php';

class PortScannerController {
    private $mysqli;
    private $model;
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new PortScannerModel($mysqli);
    }
    
    public function handleRequest($host) {
        try {
            $sanitizedHost = SecurityUtils::sanitizeInput(trim($host), 'domain', 255);
            
            if (!$sanitizedHost) {
                return [
                    'query' => ['tool' => 'port-scanner', 'host' => $host],
                    'response' => ['error' => 'Invalid host format provided.']
                ];
            }
            
            $result = $this->model->scanHost($sanitizedHost);
            
            if (isset($result['error'])) {
                return [
                    'query' => ['tool' => 'port-scanner', 'host' => $sanitizedHost],
                    'response' => ['error' => $result['error']]
                ];
            }
            
            return [
                'query' => ['tool' => 'port-scanner', 'host' => $sanitizedHost],
                'response' => $result
            ];
            
        } catch (Exception $e) {
            return [
                'query' => ['tool' => 'port-scanner', 'host' => $host ?? ''],
                'response' => ['error' => 'An internal error occurred: ' . $e->getMessage()]
            ];
        }
    }
}
?> 