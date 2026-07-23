<?php
require_once __DIR__ . '/../models/NameserverSitesModel.php';
class NameserverSitesController {
    private $model;
    public function __construct($mysqli) {
        $this->model = new NameserverSitesModel($mysqli);
    }
    public function handleRequest($nameserver) {
        $result = $this->model->getSites($nameserver);
        return [
            'query' => ['tool' => 'nameserver-sites', 'nameserver' => $nameserver],
            'response' => $result
        ];
    }

    public function addSite($nameserver, $site) {
        return $this->model->addSite($nameserver, $site);
    }
    public function updateSite($nameserver, $site) {
        return $this->model->updateSite($nameserver, $site);
    }
    public function deleteSite($nameserver) {
        return $this->model->deleteSite($nameserver);
    }
}
