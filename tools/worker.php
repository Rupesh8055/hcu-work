<?php
require_once __DIR__ . '/db_system.php';

// Controllers that the worker knows how to process
require_once __DIR__ . '/src/Controllers/ReverseWhoisLookupController.php';
require_once __DIR__ . '/src/Controllers/IpHistoryController.php';
require_once __DIR__ . '/src/Controllers/ReverseIpLookupController.php';
// ... others as needed

echo "Worker started. Waiting for jobs...\n";

while (true) {
    $mysqli->begin_transaction();
    
    // Get the highest priority pending job
    $stmt = $mysqli->prepare("SELECT id, job_type, target_data FROM background_jobs WHERE status = 'pending' ORDER BY priority DESC, created_at ASC LIMIT 1 FOR UPDATE");
    $stmt->execute();
    $res = $stmt->get_result();
    
    if ($row = $res->fetch_assoc()) {
        $jobId = $row['id'];
        $jobType = $row['job_type'];
        $targetData = $row['target_data'];
        
        // Mark as processing
        $update = $mysqli->prepare("UPDATE background_jobs SET status = 'processing' WHERE id = ?");
        $update->bind_param('s', $jobId);
        $update->execute();
        $mysqli->commit();
        
        echo "Processing job {$jobId} ({$jobType}: {$targetData})...\n";
        
        // Execute the job
        try {
            $result = null;
            if ($jobType === 'reverse-whois-lookup') {
                $controller = new \ReverseWhoisLookupController($mysqli);
                $result = $controller->handleRequest($targetData, true); // true to bypass cache read
            } else if ($jobType === 'ip-history') {
                $controller = new \IpHistoryController($mysqli);
                $result = $controller->handleRequest($targetData);
            } else if ($jobType === 'reverse-ip-lookup') {
                $controller = new \ReverseIpLookupController($mysqli);
                $result = $controller->handleRequest($targetData, true);
            } else {
                throw new Exception("Unknown job type: {$jobType}");
            }
            
            // Mark as completed
            $resultJson = json_encode($result);
            $update = $mysqli->prepare("UPDATE background_jobs SET status = 'completed', result_data = ? WHERE id = ?");
            $update->bind_param('ss', $resultJson, $jobId);
            $update->execute();
            echo "Job {$jobId} completed successfully.\n";
            
        } catch (Exception $e) {
            $errorMsg = $e->getMessage();
            $update = $mysqli->prepare("UPDATE background_jobs SET status = 'failed', error_message = ? WHERE id = ?");
            $update->bind_param('ss', $errorMsg, $jobId);
            $update->execute();
            echo "Job {$jobId} failed: {$errorMsg}\n";
        }
    } else {
        $mysqli->commit();
        // Sleep if no jobs
        sleep(2);
    }
}
