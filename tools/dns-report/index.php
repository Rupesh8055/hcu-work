<?php

// --- Security Headers ---
// Prevent XSS attacks
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'sha256-ePYRjzJpKBdkF3QpGy7dj9kg2Zn2wEOBkHvnOU8mIts='; style-src 'self' 'unsafe-inline';");
// Prevent Clickjacking
header("X-Frame-Options: DENY");
// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");
// Enable XSS filter in browsers
header("X-XSS-Protection: 1; mode=block");

// Include the backend logic file
require_once __DIR__ . '/backend.php';

// Function to render a report section as an HTML table
function render_report_section($title, $tests) {
    if (empty($tests)) {
        return;
    }

    $html = '<h3>' . htmlspecialchars($title) . '</h3>';
    $html .= '<table>';
    $html .= '<tr><th>Status</th><th>Test Case</th><th>Information</th></tr>';

    foreach ($tests as $test) {
        $status_class = strtolower($test['status']); // e.g., 'info', 'ok', 'warning'
        $info = nl2br(htmlspecialchars($test['info'])); // Preserve newlines from backend
        $html .= '<tr>';
        $html .= '<td><span class="status-' . $status_class . '">' . htmlspecialchars($test['status']) . '</span></td>';
        $html .= '<td>' . htmlspecialchars($test['case']) . '</td>';
        $html .= '<td>' . $info . '</td>';
        $html .= '</tr>';
    }

    $html .= '</table>';
    return $html;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DNS Report Tool</title>
    <link rel="icon" type="image/png" href="/favicon.png">
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; background: #f6f8fa; margin: 0; color: #333; }
        .container { max-width: 1150px; margin: 30px auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 32px; }
        h1 { font-size: 2rem; font-weight: 600; margin-bottom: 8px; }
        h2 { font-size: 1.6rem; font-weight: 600; margin-bottom: 24px; }
        h3 { font-size: 1.4rem; font-weight: 600; margin: 32px 0 16px 0; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }
        .desc { color: #555; margin-bottom: 24px; }
        .search-box { display: flex; gap: 12px; margin-bottom: 24px; }
        .search-box input { flex: 1; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
        .search-box button { background: #7a0000; color: #fff; border: none; border-radius: 6px; padding: 0 28px; font-size: 1rem; font-weight: 600; cursor: pointer; box-shadow: 0 1px 2px rgba(0,0,0,0.04); transition: background 0.2s; }
        .search-box button:hover { background: #5a0000; }
        .results-box { box-shadow:0 2px 8px rgba(0,0,0,0.08); border-radius: 12px; background:#fff; padding: 24px 32px; margin-top: 24px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px 8px; border-bottom: 1px solid #e5e7eb; }
        tr:last-child td { border-bottom: none; }
        th { color: #444; font-weight: 600; }
        td { vertical-align: top; }
        .status-info { color: #0366d6; font-weight: bold; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #dbab09; font-weight: bold; }
        .status-fail { color: #d73a49; font-weight: bold; }
        pre { background:#f3f4f6; padding:16px; border-radius:8px; overflow:auto; max-height:500px; font-size: 0.9rem; position: relative; }
        .error { color: #d73a49; font-weight: bold; padding: 16px; background: #fbeae5; border: 1px solid #d73a49; border-radius: 6px; }
        .tabs { display: flex; gap: 24px; border-bottom: 1px solid #e5e7eb; margin-bottom: 24px; }
        .tab { padding: 12px 0; font-weight: 600; color: #555; cursor: pointer; border-bottom: 3px solid transparent; text-decoration: none; }
        .tab.active { border-bottom: 3px solid #7a0000; color: #111; }
        .copy-btn { position: absolute; top: 12px; right: 12px; background: #e1e4e8; border: 1px solid #d1d5db; color: #24292e; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 600; transition: background 0.2s; }
        .copy-btn:hover { background: #d1d5db; }
        .footer { text-align: center; margin-top: 32px; color: #888; font-size: 0.9rem; }
        .footer a { color: #7a0000; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Report Tool</h1>
        <div class="desc">Get a comprehensive DNS health report for any domain, checking nameservers, SOA, MX, and other essential records.</div>
        <form class="search-box" method="get">
            <input type="text" name="domain" placeholder="Enter domain (e.g. google.com)" value="<?= isset($_GET['domain']) ? htmlspecialchars($_GET['domain']) : '' ?>" required />
            <button type="submit">Generate Report</button>
        </form>

        <?php
        if (isset($_GET['domain']) && trim($_GET['domain']) !== '') {
            $domain_input = trim($_GET['domain']);
            $tab = isset($_GET['tab']) ? $_GET['tab'] : 'html'; // Default to html tab

            // Handle Internationalized Domain Names (IDN)
            if (preg_match('/[^\x20-\x7f]/', $domain_input)) { // Check for non-ASCII characters
                if (!function_exists('idn_to_ascii')) {
                    $report = ['error' => 'The PHP intl extension is required to handle internationalized domain names (IDNs). Please install or enable it.'];
                } else {
                    $domain = idn_to_ascii($domain_input, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                    if ($domain === false) {
                        $report = ['error' => 'The provided domain name could not be processed.'];
                    }
                }
            } else {
                $domain = $domain_input;
            }

            // If the domain starts with www., remove it for the main DNS queries
            if (substr(strtolower($domain), 0, 4) === 'www.') {
                $domain = substr($domain, 4);
            }

            if (!isset($report)) { // Only generate report if no error has occurred yet
                $report = generate_dns_report($domain);
            }

            echo '<div class="results-box">';
            echo "<h2>DNS Report for <b>" . htmlspecialchars($domain_input) . "</b></h2>";

            if (isset($report['error'])) {
                echo '<div class="error">' . htmlspecialchars($report['error']) . '</div>';
            } else {
                // --- TABS ---
                $html_active = $tab === 'html' ? 'active' : '';
                $json_active = $tab === 'json' ? 'active' : '';
                echo '<div class="tabs">';
                echo '<a href="?domain=' . urlencode($domain_input) . '&tab=html" class="tab ' . $html_active . '">HTML Report</a>';
                echo '<a href="?domain=' . urlencode($domain_input) . '&tab=json" class="tab ' . $json_active . '">JSON Output</a>';
                echo '</div>';

                // --- TAB CONTENT ---
                if ($tab === 'json') {
                    $json_string = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
                    echo '<div style="position: relative;">';
                    echo '<pre id="json-output">' . htmlspecialchars($json_string) . '</pre>';
                    echo '<button class="copy-btn" onclick="copyJson()">Copy</button>';
                    echo '</div>';
                } else {
                    echo render_report_section('Parent Nameserver Tests', $report['parent_tests']);
                    echo render_report_section('Local Nameserver Tests', $report['local_tests']);
                    echo render_report_section('Start of Authority (SOA) Tests', $report['soa_tests']);
                    echo render_report_section('Mail eXchanger (MX) Tests', $report['mx_tests']);
                    echo render_report_section('WWW Record Tests', $report['www_tests']);
                }
            }
            echo '</div>';
        }
        ?>
    </div>

    <div class="footer">
        Powered by <a href="https://cyberjagrithi.com" target="_blank">CyberJagrithi</a>
    </div>

    <script>
    function copyJson() {
        const jsonText = document.getElementById('json-output').textContent;
        const copyButton = document.querySelector('.copy-btn');
        navigator.clipboard.writeText(jsonText).then(function() {
            copyButton.textContent = 'Copied!';
            setTimeout(function() {
                copyButton.textContent = 'Copy';
            }, 2000); // Reset button text after 2 seconds
        }, function(err) {
            copyButton.textContent = 'Failed!';
            console.error('Could not copy text: ', err);
        });
    }
    </script>

</body>
</html>
