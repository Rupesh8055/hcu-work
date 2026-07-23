<?php
namespace Security;

class JobQueue {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function dispatch($jobType, $targetData, $priority = 0) {
        if (!$this->mysqli) return false;
        
        // Generate a UUID v4
        $id = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );

        $stmt = $this->mysqli->prepare("INSERT INTO background_jobs (id, job_type, target_data, priority) VALUES (?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param('sssi', $id, $jobType, $targetData, $priority);
            $stmt->execute();
            $stmt->close();
            return $id;
        }
        return false;
    }

    public function getStatus($jobId) {
        if (!$this->mysqli) return null;
        $stmt = $this->mysqli->prepare("SELECT status, result_data, error_message FROM background_jobs WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param('s', $jobId);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $stmt->close();
                return $row;
            }
            $stmt->close();
        }
        return null;
    }
}
