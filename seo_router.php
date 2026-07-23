<?php
require_once __DIR__ . '/db.php';

class SeoController {
    private $mysqli;

    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }

    public function handle($type, $query) {
        $type = strtolower(trim($type));
        $query = htmlspecialchars(trim($query), ENT_QUOTES, 'UTF-8');

        $title = "Cyber Intelligence Reconnaissance - " . strtoupper($type) . ": " . $query;
        $desc = "Detailed cyber footprint analysis, hosting network mappings, and threat intelligence records for " . $type . " " . $query;

        // Custom Layouts based on node types
        $contentHtml = "";
        
        if ($type === 'ip') {
            $contentHtml = $this->renderIpDashboard($query);
        } elseif ($type === 'asn') {
            $contentHtml = $this->renderAsnDashboard($query);
        } elseif ($type === 'ns') {
            $contentHtml = $this->renderNsDashboard($query);
        } else {
            $contentHtml = "<h2>Unknown Reconnaissance Node</h2><p>The requested cyber footprint type is currently not indexed.</p>";
        }

        echo "<!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>$title - Cyber Jagrithi Intelligence</title>
            <meta name='description' content='$desc'>
            <link rel='icon' type='image/png' href='/tools/favicon.png' />
            <link rel='stylesheet' href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css' />
            <script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'></script>
            <style>
                body {
                    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
                    background: #0f172a;
                    color: #e2e8f0;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 1100px;
                    margin: 40px auto;
                    padding: 0 20px;
                }
                header {
                    border-bottom: 1px solid #334155;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }
                h1 {
                    font-size: 2.2rem;
                    color: #f1f5f9;
                    margin: 0 0 10px 0;
                }
                h1 span {
                    color: #ef4444;
                }
                h2 {
                    font-size: 1.5rem;
                    color: #38bdf8;
                    margin-top: 30px;
                    margin-bottom: 15px;
                    border-bottom: 1px solid #334155;
                    padding-bottom: 8px;
                }
                .grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .card {
                    background: #1e293b;
                    border: 1px solid #334155;
                    border-radius: 10px;
                    padding: 20px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }
                .card h3 {
                    margin-top: 0;
                    color: #94a3b8;
                    font-size: 0.85rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                .card p {
                    margin: 0;
                    font-size: 1.2rem;
                    font-weight: 600;
                    color: #f8fafc;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }
                th, td {
                    text-align: left;
                    padding: 12px 16px;
                    border-bottom: 1px solid #334155;
                }
                th {
                    background: #0f172a;
                    color: #94a3b8;
                    font-weight: 600;
                    font-size: 0.85rem;
                }
                tr:hover {
                    background: #1e293b;
                }
                .map-container {
                    width: 100%;
                    height: 350px;
                    border-radius: 10px;
                    border: 1px solid #334155;
                    margin-top: 20px;
                }
                .back-btn {
                    display: inline-block;
                    background: #334155;
                    color: #f1f5f9;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    font-size: 0.9rem;
                    margin-top: 20px;
                    transition: background 0.2s;
                }
                .back-btn:hover {
                    background: #475569;
                }
            </style>
        </head>
        <body>
            <div class='container'>
                <header>
                    <a href='/tools/' class='back-btn'>← Back to Main Console</a>
                </header>
                $contentHtml
            </div>
        </body>
        </html>";
    }

    private function renderIpDashboard($ip) {
        $ipLong = ip2long($ip);
        $ipNum = sprintf('%u', $ipLong);

        $cc = "Unknown";
        $asn = "Unknown";
        $org = "Unknown";
        $registry = "Unknown";
        $cidr = "Unknown";

        // Query offline ranges database
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT cidr, country_code, asn, isp_org, registry FROM ip_ranges WHERE ? >= start_ip_num AND ? <= end_ip_num LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('ss', $ipNum, $ipNum);
                $stmt->execute();
                $stmt->bind_result($dbCidr, $dbCc, $dbAsn, $dbOrg, $dbRegistry);
                if ($stmt->fetch()) {
                    $cidr = $dbCidr;
                    $cc = $dbCc;
                    $asn = $dbAsn ? 'AS' . $dbAsn : 'Unknown';
                    $org = $dbOrg;
                    $registry = $dbRegistry;
                }
                $stmt->close();
            }
        }

        // Fetch domains hosted here in ip_history
        $domains = [];
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT DISTINCT domain, timestamp FROM ip_history WHERE ip = ? LIMIT 20");
            if ($stmt) {
                $stmt->bind_param('s', $ip);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $domains[] = $row;
                }
                $stmt->close();
            }
        }

        $domainsRows = "";
        if (!empty($domains)) {
            foreach ($domains as $d) {
                $domainsRows .= "<tr>
                    <td><strong>" . htmlspecialchars($d['domain']) . "</strong></td>
                    <td>" . htmlspecialchars($d['timestamp']) . "</td>
                </tr>";
            }
        } else {
            $domainsRows = "<tr><td colspan='2' style='color:#64748b;font-style:italic;'>No active hosted domains registered on this IP block.</td></tr>";
        }

        $html = "
        <h1>IP Reconnaissance: <span>$ip</span></h1>
        <p style='color:#94a3b8;'>Comprehensive network attribution and hosting neighbors</p>

        <div class='grid'>
            <div class='card'>
                <h3>Registered Operator</h3>
                <p>$org</p>
            </div>
            <div class='card'>
                <h3>Country Allocation</h3>
                <p>$cc</p>
            </div>
            <div class='card'>
                <h3>Autonomous System</h3>
                <p>$asn</p>
            </div>
            <div class='card'>
                <h3>IP Subnet Prefix</h3>
                <p>$cidr ($registry)</p>
            </div>
        </div>

        <h2>Geographic Physical Mappings</h2>
        <div id='ipMap' class='map-container'></div>

        <h2>Domains Hosted on this IP Neighbors</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain Name</th>
                    <th>Last Mapping Timestamp</th>
                </tr>
            </thead>
            <tbody>
                $domainsRows
            </tbody>
        </table>

        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // Approximate mapping coordinates
                var map = L.map('ipMap').setView([20.0, 0.0], 2);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '&copy; OpenStreetMap contributors'
                }).addTo(map);

                var marker = L.marker([20.0, 0.0]).addTo(map)
                    .bindPopup('<b>$ip</b><br>$org ($cc)')
                    .openPopup();
            });
        </script>
        ";

        return $html;
    }

    private function renderAsnDashboard($asnStr) {
        $asnNum = (int)preg_replace('/[^0-9]/', '', $asnStr);
        
        $org = "Unknown Operator";
        $cc = "Unknown";
        $registry = "Unknown";

        // Query ranges to find matching ASN info
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT isp_org, country_code, registry FROM ip_ranges WHERE asn = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('i', $asnNum);
                $stmt->execute();
                $stmt->bind_result($dbOrg, $dbCc, $dbReg);
                if ($stmt->fetch()) {
                    $org = $dbOrg;
                    $cc = $dbCc;
                    $registry = $dbReg;
                }
                $stmt->close();
            }
        }

        // Fetch subnets allocated in database to this ASN
        $subnets = [];
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT cidr, country_code, registry FROM ip_ranges WHERE asn = ? LIMIT 50");
            if ($stmt) {
                $stmt->bind_param('i', $asnNum);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $subnets[] = $row;
                }
                $stmt->close();
            }
        }

        $subnetRows = "";
        if (!empty($subnets)) {
            foreach ($subnets as $sub) {
                $subnetRows .= "<tr>
                    <td><strong>" . htmlspecialchars($sub['cidr']) . "</strong></td>
                    <td>" . htmlspecialchars($sub['country_code']) . "</td>
                    <td>" . htmlspecialchars($sub['registry']) . "</td>
                </tr>";
            }
        } else {
            $subnetRows = "<tr><td colspan='3' style='color:#64748b;font-style:italic;'>No subnets dynamically matched this Autonomous System block in our index.</td></tr>";
        }

        $html = "
        <h1>ASN Reconnaissance: <span>AS$asnNum</span></h1>
        <p style='color:#94a3b8;'>Autonomous System routing policies and network footprint</p>

        <div class='grid'>
            <div class='card'>
                <h3>Autonomous Operator</h3>
                <p>$org</p>
            </div>
            <div class='card'>
                <h3>Registry Designation</h3>
                <p>$registry ($cc)</p>
            </div>
        </div>

        <h2>Indexed IP Subnet Mappings</h2>
        <table>
            <thead>
                <tr>
                    <th>CIDR Subnet</th>
                    <th>Allocation Country</th>
                    <th>Regional Registry</th>
                </tr>
            </thead>
            <tbody>
                $subnetRows
            </tbody>
        </table>
        ";

        return $html;
    }

    private function renderNsDashboard($ns) {
        $ns = strtolower(trim($ns));

        // Fetch domains utilizing this nameserver in ns_mapping
        $domains = [];
        if ($this->mysqli) {
            $stmt = $this->mysqli->prepare("SELECT DISTINCT domain, timestamp FROM ns_mapping WHERE LOWER(nameserver) = ? LIMIT 50");
            if ($stmt) {
                $stmt->bind_param('s', $ns);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    $domains[] = $row;
                }
                $stmt->close();
            }
        }

        $domainsRows = "";
        if (!empty($domains)) {
            foreach ($domains as $d) {
                $domainsRows .= "<tr>
                    <td><strong>" . htmlspecialchars($d['domain']) . "</strong></td>
                    <td>" . htmlspecialchars($d['timestamp']) . "</td>
                </tr>";
            }
        } else {
            $domainsRows = "<tr><td colspan='2' style='color:#64748b;font-style:italic;'>No active domains map to this nameserver currently.</td></tr>";
        }

        $html = "
        <h1>Nameserver Infrastructure: <span>$ns</span></h1>
        <p style='color:#94a3b8;'>Shared DNS resolution footprint clusters</p>

        <div class='grid'>
            <div class='card'>
                <h3>Nameserver Host</h3>
                <p>$ns</p>
            </div>
            <div class='card'>
                <h3>Interconnected Domain Count</h3>
                <p>" . count($domains) . " Domains</p>
            </div>
        </div>

        <h2>Domains Sharing This Nameserver Cluster</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain Name</th>
                    <th>Association Timestamp</th>
                </tr>
            </thead>
            <tbody>
                $domainsRows
            </tbody>
        </table>
        ";

        return $html;
    }
}

// Global Routing Handler
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$parts = explode('/', trim($path, '/'));
$toolIndex = array_search('tools', $parts);

if ($toolIndex !== false && isset($parts[$toolIndex + 1], $parts[$toolIndex + 2])) {
    $type  = $parts[$toolIndex + 1];
    $query = rawurldecode($parts[$toolIndex + 2]);

    // --- Existing intelligence node dashboards ---
    if (in_array(strtolower($type), ['ip', 'asn', 'ns'])) {
        $seo = new SeoController($mysqli);
        $seo->handle($type, $query);
        exit;
    }

    // --- NEW: /investigate/{domain-or-ip} — SEO-friendly investigator wrapper ---
    if (strtolower($type) === 'investigate' && !empty($query)) {
        $safeQuery = htmlspecialchars(strip_tags(trim($query)), ENT_QUOTES, 'UTF-8');
        $title     = "Threat Dossier: {$safeQuery} — Cyber Jagrithi Intelligence";
        $desc      = "Comprehensive cyber threat dossier for {$safeQuery}. Includes "
                   . "chronological DNS/WHOIS transition timelines, hostile infrastructure "
                   . "cluster detection, geolocation mapping, and reputation risk scoring.";

        // Redirect browser to the interactive SPA panel pre-loaded with the query
        $panelUrl = '/tools/network/investigator-mode/?target=' . rawurlencode($query);
        header("HTTP/1.1 301 Moved Permanently");
        header("Location: {$panelUrl}");
        exit;
    }
}