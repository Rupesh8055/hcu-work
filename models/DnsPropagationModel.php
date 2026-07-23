<?php
class DnsPropagationModel {
    public function check($domain) {
        $domain = trim($domain);
        if (empty($domain)) {
            return ['error' => 'Domain is required'];
        }
        
        $nameservers = [
            '8.8.8.8' => 'Google DNS',
            '1.1.1.1' => 'Cloudflare DNS',
            '208.67.222.222' => 'OpenDNS',
            '9.9.9.9' => 'Quad9 DNS',
            '8.8.4.4' => 'Google DNS (Secondary)'
        ];
        
        $results = [];
        
        foreach ($nameservers as $ns => $name) {
            $result = $this->queryNameserver($domain, $ns, $name);
            $results[] = $result;
        }
        
        return [
            'domain' => $domain,
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    private function queryNameserver($domain, $nameserver, $name) {
        $command = "nslookup $domain $nameserver 2>&1";
        $output = shell_exec($command);
        
        return [
            'nameserver' => $nameserver,
            'name' => $name,
            'output' => $output,
            'status' => !empty($output) ? 'success' : 'error'
        ];
    }
}
?> 