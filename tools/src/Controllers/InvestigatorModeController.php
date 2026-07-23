<?php

require_once __DIR__ . '/../Models/InvestigatorModeModel.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';
require_once __DIR__ . '/../Includes/RateLimiter.php';

class InvestigatorModeController {
    private $model;
    private $mysqli;
    private $rateLimiter;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
        $this->model = new InvestigatorModeModel($mysqli);
        $this->rateLimiter = new RateLimiter($mysqli);
    }

    /**
     * Handles an investigation dossier request.
     */
    public function handleRequest($query, $ignoreCache = false) {
        $query = trim($query);
        if (empty($query)) {
            return [
                'query' => ['target' => ''],
                'response' => ['error' => 'An active domain or IP target is required.']
            ];
        }

        // Validate target is either a valid IP or a valid domain name
        if (!filter_var($query, FILTER_VALIDATE_IP) && !preg_match('/^(?!:\/\/)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/', $query)) {
            return [
                'query' => ['target' => $query],
                'response' => ['error' => 'Invalid target format. Please provide a valid IP address or domain name.']
            ];
        }

        // Apply rate limiting (Dynamic endpoint weight cost of 10 requests since it's an expensive recursive scan)
        $userIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $limiterPass = $this->rateLimiter->check($userIp, 'investigator-mode', 10, 50, 3600, 10);
        if (!$limiterPass) {
            return [
                'query' => ['target' => $query],
                'response' => ['error' => 'Rate limit exceeded. Too many intelligence dossier requests. Please retry in an hour.']
            ];
        }

        $tool = 'investigator-mode';
        DatabaseManager::logRequest($this->mysqli, $tool, $query);

        // Standard cache checks
        if (!$ignoreCache) {
            $cache = DatabaseManager::checkCache($this->mysqli, $tool, $query);
            if ($cache['status'] === 'hit') {
                return $cache['data'];
            }
        }

        try {
            $dossier = $this->model->investigate($query);
            
            $data = [
                'query' => [
                    'tool' => $tool,
                    'target' => $query
                ],
                'response' => $dossier
            ];

            if ($dossier && !isset($dossier['error'])) {
                DatabaseManager::storeResult($this->mysqli, $tool, $query, $data);
            }

            return $data;
        } catch (Throwable $e) {
            return [
                'query' => ['tool' => $tool, 'target' => $query],
                'response' => ['error' => 'An unexpected fatal error occurred during the investigation: ' . $e->getMessage()]
            ];
        }
    }
}
