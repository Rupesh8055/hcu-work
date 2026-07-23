<?php

if (PHP_SAPI !== 'cli') {
    die("This script must be run from the CLI.");
}

require_once __DIR__ . '/../Includes/bootstrap.php';
require_once __DIR__ . '/../Includes/DatabaseManager.php';

echo "Starting Cron Refresh System (Production V4)...\n";

$sql = "SELECT tool_name, input_query 
        FROM tool_results 
        WHERE (last_updated < (NOW() - INTERVAL 10 DAY) OR status = 'expired')
        AND status != 'refreshing'
        LIMIT 50"; 

$result = $mysqli->query($sql);

if (!$result) {
    die("Error fetching expired records: " . $mysqli->error . "\n");
}

$count = 0;
while ($row = $result->fetch_assoc()) {
    $tool = $row['tool_name'];
    $input = $row['input_query'];
    
    echo "[DEBUG] Detected stale record: [$tool] for [$input]\n";

    DatabaseManager::markRefreshing($mysqli, $tool, $input);

    DatabaseManager::triggerBackgroundRefresh($tool, $input);
    
    $count++;
}

echo "Successfully triggered background refresh for $count stale records.\n";

// Trigger autonomous cybersecurity reconnaissance enrichment
echo "Starting Background Cyber Intelligence Enrichment...\n";
$phpPath = (defined('PHP_BINARY') && PHP_BINARY) ? PHP_BINARY : (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? 'c:\xampp\php\php.exe' : 'php');
$enrichmentScript = __DIR__ . '/enrichment_worker.php';
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    $cmd = "start /B " . escapeshellarg($phpPath) . " " . escapeshellarg($enrichmentScript) . " > NUL 2>&1";
    pclose(popen($cmd, "r"));
} else {
    $cmd = escapeshellcmd($phpPath) . " " . escapeshellarg($enrichmentScript) . " > /dev/null 2>&1 &";
    exec($cmd);
}
echo "Triggered autonomous intelligence enrichment worker in the background.\n";
?>