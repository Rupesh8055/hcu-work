<?php
require_once __DIR__ . '/../Includes/bootstrap.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

if (php_sapi_name() !== 'cli') {
    die("This script can only be run via CLI.\n");
}

echo "=== Cyber Intelligence Queue Processor Daemon ===\n";
echo "Started at: " . date('c') . "\n";

if (!$mysqli) {
    die("Database connection failed.\n");
}

// Map tool keys to their respective controller classes and filenames
$toolMap = [
    'abuse-lookup' => ['file' => 'AbuseLookupController.php', 'class' => 'AbuseLookupController'],
    'asn-lookup' => ['file' => 'AsnLookupController.php', 'class' => 'AsnLookupController'],
    'dns-lookup' => ['file' => 'DnsLookupController.php', 'class' => 'DnsLookupController'],
    'dns-propagation' => ['file' => 'DnsPropagationController.php', 'class' => 'DnsPropagationController'],
    'dns-report' => ['file' => 'DnsReportController.php', 'class' => 'DnsReportController'],
    'dnssec-test' => ['file' => 'DnssecTestController.php', 'class' => 'DnssecTestController'],
    'free-email-test' => ['file' => 'FreeEmailTestController.php', 'class' => 'FreeEmailTestController'],
    'global-ping' => ['file' => 'GlobalPingController.php', 'class' => 'GlobalPingController'],
    'http-headers' => ['file' => 'HttpHeadersController.php', 'class' => 'HttpHeadersController'],
    'ip-history' => ['file' => 'IpHistoryController.php', 'class' => 'IpHistoryController'],
    'ip-location' => ['file' => 'IpLocationController.php', 'class' => 'IpLocationController'],
    'mac-lookup' => ['file' => 'MacLookupController.php', 'class' => 'MacLookupController'],
    'port-scanner' => ['file' => 'PortScannerController.php', 'class' => 'PortScannerController'],
    'reverse-dns' => ['file' => 'ReverseDnsController.php', 'class' => 'ReverseDnsController'],
    'reverse-ip-lookup' => ['file' => 'ReverseIpLookupController.php', 'class' => 'ReverseIpLookupController'],
    'reverse-mx-lookup' => ['file' => 'ReverseMxController.php', 'class' => 'ReverseMxController'],
    'reverse-ns-lookup' => ['file' => 'ReverseNsLookupController.php', 'class' => 'ReverseNsLookupController'],
    'reverse-whois-lookup' => ['file' => 'ReverseWhoisLookupController.php', 'class' => 'ReverseWhoisLookupController'],
    'site-down-checker' => ['file' => 'SiteDownCheckerController.php', 'class' => 'SiteDownCheckerController'],
    'spam-database' => ['file' => 'SpamDatabaseController.php', 'class' => 'SpamDatabaseController'],
    'traceroute' => ['file' => 'TracerouteController.php', 'class' => 'TracerouteController'],
    'url-decode' => ['file' => 'UrlDecodeController.php', 'class' => 'UrlDecodeController'],
    'whois-lookup' => ['file' => 'WhoisLookupController.php', 'class' => 'WhoisLookupController']
];

$maxJobs = 100; // Exit after 100 jobs to prevent memory leaks
$jobCount = 0;
$startTime = time();

while ($jobCount < $maxJobs && (time() - $startTime) < 300) {
    // 1. Fetch the next pending job from scan_queue
    $sql = "SELECT id, tool_name, input_query, priority FROM scan_queue 
            WHERE status = 'pending' 
            ORDER BY priority DESC, created_at ASC 
            LIMIT 1";
    
    $res = $mysqli->query($sql);
    $job = $res ? $res->fetch_assoc() : null;

    if (!$job) {
        // No pending jobs, sleep and retry
        sleep(2);
        continue;
    }

    $jobId = $job['id'];
    $tool = $job['tool_name'];
    $input = $job['input_query'];
    $priority = $job['priority'];

    echo "[JOB #{$jobId}] Processing: [$tool] for [$input] (Priority: $priority)...\n";
    $jobCount++;

    // 2. Mark job as processing
    $stmt = $mysqli->prepare("UPDATE scan_queue SET status = 'processing', started_at = NOW() WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param('i', $jobId);
        $stmt->execute();
        $stmt->close();
    }

    // 3. Execute job using the mapped controller
    if (!isset($toolMap[$tool])) {
        markJobFailed($mysqli, $jobId, "Tool mapping not found for tool: {$tool}");
        continue;
    }

    $config = $toolMap[$tool];
    $filePath = __DIR__ . '/../Controllers/' . $config['file'];
    
    if (!file_exists($filePath)) {
        markJobFailed($mysqli, $jobId, "Controller file not found: {$filePath}");
        continue;
    }

    try {
        require_once $filePath;
        $className = $config['class'];
        $controller = new $className($mysqli);

        $jobStart = microtime(true);
        
        // Run with ignoreCache = true to force refresh
        if ($tool === 'dns-lookup' || $tool === 'dns-propagation') {
            if (strpos($input, '|') !== false) {
                list($domain, $type) = explode('|', $input, 2);
                $controller->handleRequest($domain, $type, true);
            } else {
                $controller->handleRequest($input, 'ANY', true);
            }
        } else {
            $controller->handleRequest($input, true);
        }

        $elapsed = round((microtime(true) - $jobStart) * 1000, 2);
        $peakMem = round(memory_get_peak_usage(true) / 1024 / 1024, 2);

        echo "   [SUCCESS] Completed in {$elapsed}ms | Peak Memory: {$peakMem}MB\n";

        // Mark job as completed
        $stmtComp = $mysqli->prepare("UPDATE scan_queue SET status = 'completed', completed_at = NOW() WHERE id = ?");
        if ($stmtComp) {
            $stmtComp->bind_param('i', $jobId);
            $stmtComp->execute();
            $stmtComp->close();
        }

    } catch (Throwable $e) {
        $errStr = $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine();
        markJobFailed($mysqli, $jobId, $errStr);
    }
}

echo "=== Daemon Exiting (Job limit or execution timeout reached) ===\n";

function markJobFailed($mysqli, $jobId, $error) {
    echo "   [FAILED] Error: {$error}\n";
    $stmt = $mysqli->prepare("UPDATE scan_queue SET status = 'failed', error_message = ?, completed_at = NOW() WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param('si', $error, $jobId);
        $stmt->execute();
        $stmt->close();
    }
}
