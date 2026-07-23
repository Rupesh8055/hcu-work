<?php
class FreeEmailTestModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function test($email) {
        if (empty($email)) return ['error' => 'Email address is required.'];
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return ['error' => 'Invalid email format provided.'];
        $email = strtolower(trim($email));
        $domain = substr(strrchr($email, "@"), 1);
        $isFree = false; $isDisposable = false;
        if ($this->mysqli && !$this->mysqli->connect_errno) {
            $stmt = $this->mysqli->prepare("SELECT 1 FROM free_email_domains WHERE domain = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param("s", $domain);
                $stmt->execute();
                $stmt->store_result();
                if ($stmt->num_rows > 0) $isFree = true;
                $stmt->close();
            }
        }
        $type = 'Corporate/Private';
        if ($isDisposable) $type = 'Disposable Email';
        elseif ($isFree) $type = 'Free Email Provider';
        return [
            'email' => $email,
            'domain' => $domain,
            'is_free_email' => $isFree || $isDisposable,
            'is_disposable' => $isDisposable,
            'provider_type' => $type,
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => 'internal_database'
        ];
    }
}