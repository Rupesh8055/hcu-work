<?php
namespace Security;

class NetworkClient {
    private $mysqli;
    private $maxFailures = 3;
    private $resetTimeout = 60; // seconds before transitioning from OPEN to HALF_OPEN

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function fetchWithCircuitBreaker($serviceName, $callable) {
        $state = $this->getCircuitState($serviceName);
        
        if ($state === 'open') {
            throw new \Exception("Circuit breaker is OPEN for {$serviceName}. Service temporarily unavailable.");
        }

        try {
            $result = call_user_func($callable);
            
            // If we were half-open and succeeded, close the circuit
            if ($state === 'half_open') {
                $this->resetCircuit($serviceName);
            }
            
            return $result;
        } catch (\Exception $e) {
            $this->recordFailure($serviceName);
            throw $e;
        }
    }

    private function getCircuitState($serviceName) {
        if (!$this->mysqli) return 'closed';
        
        $stmt = $this->mysqli->prepare("SELECT failures, state, UNIX_TIMESTAMP(last_failure) as last_failure_ts FROM circuit_breakers WHERE service_name = ?");
        if ($stmt) {
            $stmt->bind_param('s', $serviceName);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $stmt->close();
                
                if ($row['state'] === 'open') {
                    if (time() - $row['last_failure_ts'] > $this->resetTimeout) {
                        $this->updateCircuitState($serviceName, 'half_open');
                        return 'half_open';
                    }
                    return 'open';
                }
                return $row['state'];
            } else {
                // Initialize circuit breaker
                $stmt->close();
                $insert = $this->mysqli->prepare("INSERT INTO circuit_breakers (service_name) VALUES (?)");
                $insert->bind_param('s', $serviceName);
                $insert->execute();
            }
        }
        return 'closed';
    }

    private function recordFailure($serviceName) {
        if (!$this->mysqli) return;
        
        // Use single query to increment failure and conditionally open circuit
        $sql = "UPDATE circuit_breakers 
                SET failures = failures + 1, 
                    last_failure = CURRENT_TIMESTAMP,
                    state = CASE WHEN failures + 1 >= ? THEN 'open' ELSE state END
                WHERE service_name = ?";
        $stmt = $this->mysqli->prepare($sql);
        if ($stmt) {
            $stmt->bind_param('is', $this->maxFailures, $serviceName);
            $stmt->execute();
            $stmt->close();
        }
    }

    private function resetCircuit($serviceName) {
        if (!$this->mysqli) return;
        $stmt = $this->mysqli->prepare("UPDATE circuit_breakers SET failures = 0, state = 'closed' WHERE service_name = ?");
        if ($stmt) {
            $stmt->bind_param('s', $serviceName);
            $stmt->execute();
            $stmt->close();
        }
    }

    private function updateCircuitState($serviceName, $newState) {
        if (!$this->mysqli) return;
        $stmt = $this->mysqli->prepare("UPDATE circuit_breakers SET state = ? WHERE service_name = ?");
        if ($stmt) {
            $stmt->bind_param('ss', $newState, $serviceName);
            $stmt->execute();
            $stmt->close();
        }
    }
    
    // Example socket connection pool wrapper with timeouts
    public function openSocket($host, $port, $timeout = 5) {
        return $this->fetchWithCircuitBreaker("socket:{$host}:{$port}", function() use ($host, $port, $timeout) {
            $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
            if (!$fp) {
                throw new \Exception("Socket connection failed to {$host}:{$port}");
            }
            stream_set_timeout($fp, $timeout);
            return $fp;
        });
    }
}
