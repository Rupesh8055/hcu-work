<?php
require_once __DIR__ . '/db_system.php';

$sql = "CREATE TABLE IF NOT EXISTS dns_resolvers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(50) NOT NULL,
    latitude DECIMAL(10, 8) NULL,
    longitude DECIMAL(11, 8) NULL,
    status VARCHAR(20) DEFAULT 'active'
)";

if (!$mysqli->query($sql)) {
    die("Error creating dns_resolvers: " . $mysqli->error);
}

$mysqli->query("TRUNCATE TABLE dns_resolvers");

$resolvers = [
    ['ip' => '8.8.8.8', 'name' => 'Google DNS', 'loc' => 'US', 'lat' => 33.7490, 'lon' => -84.3880],
    ['ip' => '1.1.1.1', 'name' => 'Cloudflare', 'loc' => 'Global', 'lat' => 34.0522, 'lon' => -118.2437],
    ['ip' => '208.67.222.222', 'name' => 'OpenDNS', 'loc' => 'US', 'lat' => 40.7128, 'lon' => -74.0060],
    ['ip' => '9.9.9.9', 'name' => 'Quad9', 'loc' => 'CH', 'lat' => 47.6062, 'lon' => -122.3321],
    ['ip' => '76.76.2.0', 'name' => 'ControlD', 'loc' => 'US', 'lat' => 38.8951, 'lon' => -77.0364],
    ['ip' => '1.0.0.1', 'name' => 'Cloudflare', 'loc' => 'HK', 'lat' => 22.3193, 'lon' => 114.1694],
    ['ip' => '8.8.4.4', 'name' => 'Google DNS', 'loc' => 'SG', 'lat' => 1.3521, 'lon' => 103.8198],
    ['ip' => '119.29.29.29', 'name' => 'DNSPod', 'loc' => 'CN', 'lat' => 19.0760, 'lon' => 72.8777],
    ['ip' => '114.114.114.114', 'name' => '114DNS', 'loc' => 'CN', 'lat' => 39.9042, 'lon' => 116.4074],
    ['ip' => '185.228.168.9', 'name' => 'CleanBrowsing', 'loc' => 'NL', 'lat' => 51.9244, 'lon' => 4.4777],
    ['ip' => '156.154.70.1', 'name' => 'Neustar', 'loc' => 'US', 'lat' => 37.7749, 'lon' => -122.4194],
    ['ip' => '195.46.39.39', 'name' => 'SafeDNS', 'loc' => 'EU', 'lat' => 52.5200, 'lon' => 13.4050],
];

$stmt = $mysqli->prepare("INSERT INTO dns_resolvers (ip, name, location, latitude, longitude) VALUES (?, ?, ?, ?, ?)");
foreach ($resolvers as $res) {
    $stmt->bind_param("sssdd", $res['ip'], $res['name'], $res['loc'], $res['lat'], $res['lon']);
    $stmt->execute();
}
$stmt->close();
echo "Resolvers created and populated.\n";
