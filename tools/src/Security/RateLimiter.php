<?php
namespace Security;

require_once __DIR__ . '/../Includes/RateLimiter.php';

class RateLimiter extends \RateLimiter {
    public function __construct($mysqli) {
        parent::__construct($mysqli);
    }
}
