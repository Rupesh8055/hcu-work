<?php
require_once __DIR__ . '/../models/SiteDownCheckerModel.php';

class SiteDownCheckerController {
    private $mysqli;
    private $model;
    
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new SiteDownCheckerModel($mysqli);
    }
    
    public function handleRequest($rawUrl) {
        try {
            if (empty($rawUrl)) {
                return [
                    'query' => ['tool' => 'site-down-checker', 'url' => ''],
                    'response' => ['error' => 'URL parameter is required.']
                ];
            }
            
            if (!preg_match('/^https?:\/\//', $rawUrl)) {
                $rawUrl = 'https://' . $rawUrl;
            }
            
            $url = SecurityUtils::sanitizeInput($rawUrl, 'url', 500);
            
            if (!$url) {
                return [
                    'query' => ['tool' => 'site-down-checker', 'url' => $rawUrl],
                    'response' => ['error' => 'Invalid URL format provided.']
                ];
            }
            
            $result = $this->model->check($url);
            
            return [
                'query' => ['tool' => 'site-down-checker', 'url' => $url],
                'response' => $result
            ];
            
        } catch (Exception $e) {
            return [
                'query' => ['tool' => 'site-down-checker', 'url' => $rawUrl ?? ''],
                'response' => ['error' => 'An internal error occurred: ' . $e->getMessage()]
            ];
        }
    }
}
?>