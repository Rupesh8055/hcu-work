<?php
require_once __DIR__ . '/../models/ReverseMxModel.php';
class ReverseMxController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new ReverseMxModel($mysqli);
    }
    public function handleRequest($mx) {
        if (empty($mx)) {
            return [
                'query' => ['tool' => 'reverse-mx-lookup', 'mailserver' => $mx],
                'response' => [
                    'domain_count' => 0,
                    'domains' => [],
                    'mx_domain' => $mx,
                    'error' => 'Please provide a valid mail server domain.'
                ]
            ];
        }
        
        $mx = strtolower(trim($mx));
        
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $mx)) {
            return [
                'query' => ['tool' => 'reverse-mx-lookup', 'mailserver' => $mx],
                'response' => [
                    'domain_count' => 0,
                    'domains' => [],
                    'mx_domain' => $mx,
                    'error' => 'Invalid domain format. Please enter a valid mail server domain.'
                ]
            ];
        }
        
        $mxHosts = [];
        if (getmxrr($mx, $hosts)) {
            foreach ($hosts as $host) {
                $mxHosts[] = strtolower(rtrim($host, '.'));
            }
        }
        
        if (empty($mxHosts)) {
            $mxHosts[] = $mx;
        }
        
        $domains = $this->model->getDomainsByMx($mxHosts);
        
        return [
            'query' => ['tool' => 'reverse-mx-lookup', 'mailserver' => $mx],
            'response' => [
                'domain_count' => count($domains),
                'domains' => $domains,
                'mx_domain' => $mx,
                'error' => count($domains) > 0 ? '' : 'No domains found using this mail server.'
            ]
        ];
    }
    public function addDomain($domain, $mx_record) {
        return $this->model->addDomain($domain, $mx_record);
    }
    public function updateDomain($domain, $mx_record) {
        return $this->model->updateDomain($domain, $mx_record);
    }
    public function deleteDomain($domain) {
        return $this->model->deleteDomain($domain);
    }
}