<?php

if (PHP_SAPI !== 'cli') {
    die("This script must be run from the CLI.");
}

if ($argc < 3) {
    die("Usage: php background_refresh.php <tool_name> <input>\n");
}

$tool = $argv[1];
$input = $argv[2];

require_once __DIR__ . '/../Includes/bootstrap.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

$toolMap = [
    'abuse-lookup'        => ['file' => 'AbuseLookupController.php', 'class' => 'AbuseLookupController'],
    'asn-lookup'          => ['file' => 'AsnLookupController.php', 'class' => 'AsnLookupController'],
    'dns-lookup'          => ['file' => 'DnsLookupController.php', 'class' => 'DnsLookupController'],
    'dns-propagation'     => ['file' => 'DnsPropagationController.php', 'class' => 'DnsPropagationController'],
    'dns-report'          => ['file' => 'DnsReportController.php', 'class' => 'DnsReportController'],
    'dnssec-test'         => ['file' => 'DnssecTestController.php', 'class' => 'DnssecTestController'],
    'free-email-test'     => ['file' => 'FreeEmailTestController.php', 'class' => 'FreeEmailTestController'],
    'global-ping'         => ['file' => 'GlobalPingController.php', 'class' => 'GlobalPingController'],
    'http-headers'        => ['file' => 'HttpHeadersController.php', 'class' => 'HttpHeadersController'],
    'intelligence-search' => ['file' => 'IntelligenceSearchController.php', 'class' => 'IntelligenceSearchController'],
    'ip-history'          => ['file' => 'IpHistoryController.php', 'class' => 'IpHistoryController'],
    'ip-location'         => ['file' => 'IpLocationController.php', 'class' => 'IpLocationController'],
    'mac-lookup'          => ['file' => 'MacLookupController.php', 'class' => 'MacLookupController'],
    'port-scanner'        => ['file' => 'PortScannerController.php', 'class' => 'PortScannerController'],
    'reverse-dns'         => ['file' => 'ReverseDnsController.php', 'class' => 'ReverseDnsController'],
    'reverse-ip-lookup'   => ['file' => 'ReverseIpLookupController.php', 'class' => 'ReverseIpLookupController'],
    'reverse-mx-lookup'   => ['file' => 'ReverseMxController.php', 'class' => 'ReverseMxController'],
    'reverse-ns-lookup'   => ['file' => 'ReverseNsLookupController.php', 'class' => 'ReverseNsLookupController'],
    'reverse-whois-lookup' => ['file' => 'ReverseWhoisLookupController.php', 'class' => 'ReverseWhoisLookupController'],
    'site-down-checker'   => ['file' => 'SiteDownCheckerController.php', 'class' => 'SiteDownCheckerController'],
    'spam-database'       => ['file' => 'SpamDatabaseController.php', 'class' => 'SpamDatabaseController'],
    'traceroute'          => ['file' => 'TracerouteController.php', 'class' => 'TracerouteController'],
    'url-decode'          => ['file' => 'UrlDecodeController.php', 'class' => 'UrlDecodeController'],
    'whois-lookup'        => ['file' => 'WhoisLookupController.php', 'class' => 'WhoisLookupController']
];

if (!isset($toolMap[$tool])) {
    exit(1);
}

$config = $toolMap[$tool];
require_once TOOLS_ROOT . '/src/Controllers/' . $config['file'];

try {
    $controllerClass = $config['class'];
    $controller = new $controllerClass($mysqli);

    if ($tool === 'dns-lookup' || $tool === 'dns-propagation') {
        $parts = explode('|', $input);
        $domain = $parts[0] ?? $input;
        $type = $parts[1] ?? 'A';
        $data = $controller->handleRequest($domain, $type, true); 
    } else {
        $data = $controller->handleRequest($input, true); 
    }

    if ($data && (!isset($data['response']['error']))) {
        // Success
    } else {
        // Failed
    }
} catch (Throwable $t) {
    exit(1);
}
?>