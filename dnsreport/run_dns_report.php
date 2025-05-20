<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain'])) {
    $domain = escapeshellarg($_POST['domain']);

    // Call Node.js script
    $outputDir = __DIR__;
    $cmd = "node dnsreport_final.js <<< \"$domain\\ny\n\"";

    // Run the command and capture output
    exec($cmd . " 2>&1", $output, $returnCode);

    if ($returnCode !== 0) {
        header("Location: index.php?error=Failed to run DNS check.");
        exit;
    }

    // Find the last saved report file
    $pattern = $outputDir . "/dns_report_" . str_replace('.', '_', $_POST['domain']) . "_*.txt";
    $files = glob($pattern);
    rsort($files); // latest first

    if (count($files) > 0) {
        $reportFile = basename($files[0]);
        header("Location: index.php?output=$reportFile&domain=" . urlencode($_POST['domain']));
    } else {
        header("Location: index.php?error=Report not found.");
    }
} else {
    header("Location: index.php?error=Invalid request.");
}
