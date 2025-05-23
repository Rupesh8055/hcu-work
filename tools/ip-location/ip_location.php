<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
require 'vendor/autoload.php';
use GeoIp2\Database\Reader;

$result = null;
$error = null;

if (isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    $ip = $_GET['ip'];
    try {
        if (!file_exists('GeoLite2-City.mmdb')) {
            $error = 'GeoLite2-City.mmdb file not found';
        } else {
            $reader = new Reader('GeoLite2-City.mmdb');
            $record = $reader->city($ip);
            $result = [
                'ip' => $ip,
                'country' => $record->country->name ?? 'Unknown',
                'city' => $record->city->name ?? 'Unknown',
                'region' => $record->subdivisions[0]->name ?? 'Unknown',
                'postal_code' => $record->postal->code ?? 'Unknown',
                'latitude' => $record->location->latitude ?? 0,
                'longitude' => $record->location->longitude ?? 0,
                'timezone' => $record->location->timeZone ?? 'Unknown'
            ];
        }
    } catch (Exception $e) {
        $error = 'Invalid IP or database error: ' . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IP Location Finder</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; background: #f6f8fa; margin: 0; }
        .container { max-width: 1150px; margin: 30px auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 32px 32px 24px 32px; }
        h1 { font-size: 2rem; font-weight: 600; margin-bottom: 8px; }
        .desc { color: #555; margin-bottom: 24px; }
        .search-box { display: flex; gap: 12px; margin-bottom: 24px; }
        .search-box input { flex: 1; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
        .search-box button { background: #7a0000; color: #fff; border: none; border-radius: 6px; padding: 0 28px; font-size: 1rem; font-weight: 600; cursor: pointer; box-shadow: 0 1px 2px rgba(0,0,0,0.04); transition: background 0.2s; }
        .search-box button:hover { background: #5a0000; }
        .results-header { font-size: 1.2rem; font-weight: 500; margin: 24px 0 8px 0; }
        .results-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
        .results-table th, .results-table td { text-align: left; padding: 12px 8px; border-bottom: 1px solid #e5e7eb; }
        .results-table th { background: #f3f4f6; color: #444; font-weight: 600; }
        .results-table tr:last-child td { border-bottom: none; }
        .map-container { width: 100%; height: 320px; border-radius: 8px; overflow: hidden; margin-bottom: 16px; background: #e5e7eb; display: flex; align-items: center; justify-content: center; }
        .error { color: red; margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP Location Finder</h1>
        <div class="desc">This tool will display geographic information about a supplied IP address including city, country, latitude, longitude and more.</div>
        <form class="search-box" method="get">
            <input type="text" name="ip" placeholder="Enter IP address" value="<?php echo isset($_GET['ip']) ? htmlspecialchars($_GET['ip']) : ''; ?>" required />
            <button type="submit">Find</button>
        </form>
        <?php if ($error): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($result): ?>
            <div class="results-header">Results</div>
            <table class="results-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>Region</th>
                        <th>City</th>
                        <th>Postal Code</th>
                        <th>Latitude</th>
                        <th>Longitude</th>
                        <th>Timezone</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><?php echo htmlspecialchars($result['ip']); ?></td>
                        <td><?php echo htmlspecialchars($result['country']); ?></td>
                        <td><?php echo htmlspecialchars($result['region']); ?></td>
                        <td><?php echo htmlspecialchars($result['city']); ?></td>
                        <td><?php echo htmlspecialchars($result['postal_code']); ?></td>
                        <td><?php echo htmlspecialchars($result['latitude']); ?></td>
                        <td><?php echo htmlspecialchars($result['longitude']); ?></td>
                        <td><?php echo htmlspecialchars($result['timezone']); ?></td>
                    </tr>
                </tbody>
            </table>
            <div class="map-container">Map for <?php echo htmlspecialchars($result['latitude']); ?>, <?php echo htmlspecialchars($result['longitude']); ?></div>
        <?php endif; ?>
    </div>
</body>
</html>