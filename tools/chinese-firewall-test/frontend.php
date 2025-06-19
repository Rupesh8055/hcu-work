<?php
// frontend.php - Frontend for Chinese Firewall Test
// This file displays the UI and fetches data from backend.php (backend)

// Function to make a server-side request to the backend API
function fetch_gfw_results($domain) {
    // Dynamically construct the backend URL.
    // IMPORTANT: The backend.php should be running on a DIFFERENT PORT
    // (e.g., 8001) using a separate PHP built-in server instance.
    // This resolves the "website keeps loading" issue.
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    // We'll hardcode the backend port to 8001, assuming you run it there.
    // The host remains the same (e.g., localhost).
    $backend_host = 'localhost'; // Or your specific host if not localhost
    $backend_port = '8001'; // IMPORTANT: This must be the port backend.php is listening on
    $backend_url = "{$protocol}://{$backend_host}:{$backend_port}/backend.php?domain=" . urlencode($domain);

    // Temporarily remove @ to allow warnings/errors from file_get_contents to be visible.
    // This is crucial for debugging.
    $response = file_get_contents($backend_url);

    if ($response === FALSE) {
        // Check if allow_url_fopen is disabled, a common reason for this failure
        if (ini_get('allow_url_fopen') == '0') {
            return ['error' => 'PHP setting "allow_url_fopen" is disabled. This function requires it to fetch data from the backend. Please enable it in your php.ini.'];
        }
        // General error if file_get_contents fails for other reasons
        return ['error' => 'Could not connect to the backend API or API returned an error. Make sure backend.php is running on ' . htmlspecialchars("{$backend_host}:{$backend_port}") . '. Check server logs for backend.php for more details. Attempted URL: ' . htmlspecialchars($backend_url)];
    }

    $data = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        // Handle JSON decoding error. Show the raw response to help diagnose malformed JSON.
        return ['error' => 'Invalid JSON response from backend API. Raw response: ' . htmlspecialchars($response)];
    }

    return $data;
}

// Start of HTML output
echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Chinese Firewall Test</title>';
echo '<link rel="icon" type="image/png" href="/favicon.png">';
echo '<style>
    body { font-family: Segoe UI, Arial, sans-serif; background: #f6f8fa; margin: 0; }
    .container { max-width: 1150px; margin: 30px auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 32px 32px 24px 32px; }
    h1 { font-size: 2rem; font-weight: 600; margin-bottom: 8px; }
    .desc { color: #555; margin-bottom: 8px; }
    .note { color: #888; font-size: 1rem; margin-bottom: 24px; }
    .search-box { display: flex; gap: 12px; margin-bottom: 24px; }
    .search-box input { flex: 1; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
    .search-box button { background: #7a0000; color: #fff; border: none; border-radius: 6px; padding: 0 28px; font-size: 1rem; font-weight: 600; cursor: pointer; box-shadow: 0 1px 2px rgba(0,0,0,0.04); transition: background 0.2s; }
    .search-box button:hover { background: #5a0000; }
    .tabs { display: flex; gap: 24px; border-bottom: 1px solid #e5e7eb; margin-bottom: 0; }
    .tab { padding: 12px 0; font-weight: 500; color: #222; cursor: pointer; border-bottom: 2px solid transparent; text-decoration: none; }
    .tab.active { border-bottom: 2px solid #7a0000; color: #7a0000; }
    .results-header { font-size: 1.2rem; font-weight: 500; margin: 24px 0 8px 0; }
    .results-section { font-size: 1.1rem; font-weight: 600; margin: 32px 0 8px 0; }
    .results-count { color: #666; font-size: 1rem; margin-bottom: 8px; }
    .results-note { color: #888; font-size: 1rem; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; padding: 18px 8px; vertical-align: top; }
    th { background: #f3f4f6; color: #444; font-weight: 600; border-bottom: 1px solid #e5e7eb; font-size: 1.05rem; }
    tr:nth-child(even) { background: #fafbfc; }
    tr:hover { background: #f1f5f9; }
    .icon-btn { opacity: 0.6; cursor: pointer; display: inline-block; font-size: 22px; margin-left: 8px; transition: opacity 0.2s; }
    .icon-btn:hover { opacity: 1; }
    .status-error { color: #dc2626; font-size: 1.2rem; }
    .status-ok { color: #059669; font-size: 1.2rem; }
    .map-placeholder { width: 100%; height: 260px; background: #ededed; border-radius: 8px; margin: 24px 0 24px 0; display: flex; align-items: center; justify-content: center; position: relative; }
    .leaflet-credit { position: absolute; bottom: 8px; right: 16px; font-size: 0.95rem; color: #888; }
    .summary-item { margin-bottom: 10px; padding: 8px 0; border-bottom: 1px dashed #e2e8f0; }
    .summary-item:last-child { border-bottom: none; }
    .summary-status { font-weight: 600; }
    .status-positive { color: #059669; } /* Green */
    .status-negative { color: #dc2626; } /* Red */
    .status-neutral { color: #f59e0b; } /* Orange/Yellow */
</style></head><body>';

echo '<div class="container">';
echo '<h1>Chinese Firewall Test</h1>';
echo '<div class="desc">Checks whether a site is blocked by the Great Firewall of China. This test checks across a number of servers from various locations in mainland China to determine if access to the site provided is possible from behind the Great Firewall of China.</div>';
echo '<div class="note">This test checks for symptoms of DNS poisoning, one of the more common methods used by the Chinese government to block access to websites.</div>';
echo '<form class="search-box" method="get">';
echo '<input type="text" name="domain" placeholder="Enter domain" value="' . (isset($_GET['domain']) ? htmlspecialchars($_GET['domain']) : '') . '" required />';
echo '<button type="submit">Check</button>';
echo '</form>';

// Process results if a domain is submitted
if (isset($_GET['domain']) && trim($_GET['domain']) !== '') {
    $tab = isset($_GET['tab']) ? $_GET['tab'] : 'summary'; // Default to summary tab
    $domain = trim($_GET['domain']);

    // Call the backend API to get analysis results
    $analysis_results = fetch_gfw_results($domain);

    // Check for errors from the backend API
    if (isset($analysis_results['error'])) {
        echo '<div style="background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 8px; margin-top: 20px;">';
        echo '<strong>Error:</strong> ' . htmlspecialchars($analysis_results['error']);
        echo '</div>';
    } else {
        // Map the results to the variables expected by the existing HTML structure
        $expected = $analysis_results['local_ip'] ?? 'N/A'; // Use null coalescing operator for safety
        $servers = [];
        if (isset($analysis_results['trusted_dns_results'])) {
            foreach ($analysis_results['trusted_dns_results'] as $trusted_result) {
                // Check if 'ip' key exists before accessing it
                $ip_address = $trusted_result['ip'] ?? 'Error: IP not found';
                $status_bool = !strpos($ip_address, 'Error') !== false && !strpos($ip_address, 'No valid IP') !== false;
                $servers[] = [
                    $trusted_result['dns_server'] ?? 'N/A',
                    $ip_address,
                    $status_bool
                ];
            }
        }

        $summary_active = $tab === 'summary' ? 'active' : '';
        $html_active = $tab === 'html' ? 'active' : '';
        $json_active = $tab === 'json' ? 'active' : '';

        echo '<div style="background:#fff;border-radius:12px 12px 0 0;box-shadow:0 2px 8px rgba(0,0,0,0.08);padding:0 32px 0 32px;margin-bottom:0;">';
        echo '<div class="tabs">';
        echo '<a href="?domain=' . urlencode($domain) . '&tab=summary" class="tab ' . $summary_active . '" id="summaryTab">Summary</a>';
        echo '<a href="?domain=' . urlencode($domain) . '&tab=html" class="tab ' . $html_active . '" id="htmlTab">HTML</a>';
        echo '<a href="?domain=' . urlencode($domain) . '&tab=json" class="tab ' . $json_active . '" id="jsonTab">JSON</a>';
        echo '</div>';
        echo '</div>';

        echo '<div style="position:relative;box-shadow:0 2px 8px rgba(0,0,0,0.08);border-radius:0 0 12px 12px;background:#fff;padding:32px 32px 16px 32px;margin-bottom:32px;">';
        echo '<div style="position:absolute;top:24px;right:32px;display:flex;gap:12px;">';
        echo '<span title="Copy" class="icon-btn" onclick="copyJson()">📋</span>';
        echo '<span title="Download" class="icon-btn" onclick="downloadJson()">⬇️</span>';
        echo '</div>'; // Close absolute positioned div

        echo '<div class="results-header" style="margin-top:0;">Chinese firewall test results for ' . htmlspecialchars($domain) . '</div>';
        // Map placeholder (China region)
        echo '<div class="map-placeholder">';
        echo '<span style="position:absolute;top:8px;left:8px;font-size:1.3rem;font-weight:600;">+</span>';
        echo '<span style="position:absolute;top:36px;left:8px;font-size:1.3rem;font-weight:600;">-</span>';
        echo '<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/1/1b/China_blank_map.png/800px-China_blank_map.png" alt="China map" style="width:100%;height:100%;object-fit:cover;border-radius:8px;filter:grayscale(0.15);">';
        echo '<span class="leaflet-credit">Leaflet | © CARTO © OpenStreetMap contributors</span>';
        echo '</div>';
        
        // Summary View
        echo '<div id="summaryView" ' . ($tab === 'summary' ? '' : 'style="display:none;"') . '>';
        echo '<div style="background:#f3f4f6;padding:12px 18px;font-size:1.05rem;font-weight:500;border-radius:6px 6px 0 0;">OVERALL SUMMARY</div>';
        echo '<div style="background:#fff;padding:12px 18px 12px 18px;font-size:1.05rem;border-radius:0 0 6px 6px;margin-bottom:18px;border-bottom:1px solid #e5e7eb;">';
        
        // Generate summary content
        echo '<div class="summary-item"><strong>Overall GFW Status:</strong> <span class="summary-status status-';
        if (strpos($analysis_results['gfw_status'], 'No GFW Issues') !== false) {
            echo 'positive';
        } elseif (strpos($analysis_results['gfw_status'], 'Suspected') !== false || strpos($analysis_results['gfw_status'], 'Detected') !== false || strpos($analysis_results['gfw_status'], 'Failed') !== false) {
            echo 'negative';
        } else {
            echo 'neutral';
        }
        echo '">' . htmlspecialchars($analysis_results['gfw_status'] ?? 'N/A') . '</span></div>';

        echo '<div class="summary-item"><strong>DNS Poisoning Detected:</strong> <span class="summary-status status-';
        echo ($analysis_results['dns_poisoning_detected'] ?? false) ? 'negative">Yes' : 'positive">No';
        echo '</span></div>';

        echo '<div class="summary-item"><strong>Local DNS IP:</strong> ' . htmlspecialchars($analysis_results['local_ip'] ?? 'N/A') . '</div>';

        echo '<div class="summary-item"><strong>TCP Connectivity:</strong> <span class="summary-status status-';
        echo ($analysis_results['tcp_connectivity']['accessible'] ?? false) ? 'positive">Accessible' : 'negative">Blocked';
        echo '</span></div>';

        if (($analysis_results['tcp_connectivity']['gfw_rst_detected'] ?? false)) {
            echo '<div class="summary-item"><strong>TCP RST Detected:</strong> <span class="summary-status status-negative">Yes</span></div>';
        }

        echo '<div class="summary-item"><strong>HTTP Accessibility:</strong> <span class="summary-status status-';
        echo ($analysis_results['http_accessible'] ?? false) ? 'positive">Accessible' : 'negative">Blocked';
        echo '</span></div>';
        
        if (($analysis_results['gfw_block_suspected'] ?? false)) {
             echo '<div class="summary-item"><strong>HTTP Block Suspected:</strong> <span class="summary-status status-negative">Yes</span></div>';
        }

        echo '<div class="summary-item"><strong>Tested On:</strong> ' . htmlspecialchars($analysis_results['timestamp'] ?? 'N/A') . '</div>';

        echo '</div>'; // Close summary content div
        echo '</div>'; // Close summaryView

        // Expected value (remains for HTML/JSON tabs if needed, but not primary for summary)
        echo '<div style="background:#f3f4f6;padding:12px 18px;font-size:1.05rem;font-weight:500;border-radius:6px 6px 0 0;margin-top:18px;">EXPECTED VALUE OF DNS A RECORDS</div>';
        echo '<div style="background:#fff;padding:12px 18px 12px 18px;font-size:1.05rem;border-radius:0 0 6px 6px;margin-bottom:18px;border-bottom:1px solid #e5e7eb;">' . htmlspecialchars($expected) . '</div>';

        // Table (HTML View)
        echo '<div id="htmlView" ' . ($tab === 'html' ? '' : 'style="display:none;"') . '>';
        echo '<table style="margin-top:0;"><tr>';
        echo '<th style="background:#f3f4f6;font-size:0.95rem;color:#6b7280;font-weight:500;letter-spacing:0.04em;">SERVER LOCATION</th>';
        echo '<th style="background:#f3f4f6;font-size:0.95rem;color:#6b7280;font-weight:500;letter-spacing:0.04em;">RECORDS RETURNED</th>';
        echo '<th style="background:#f3f4f6;font-size:0.95rem;color:#6b7280;font-weight:500;letter-spacing:0.04em;">STATUS</th>';
        echo '</tr>';
        foreach ($servers as $row) {
            $status_icon = $row[2] ? '<span class="status-ok">✔</span>' : '<span class="status-error">✖</span>';
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row[0]) . '</td>';
            echo '<td>' . htmlspecialchars($row[1]) . '</td>';
            echo '<td>' . $status_icon . '</td>';
            echo '</tr>';
        }
        echo '</table>';
        echo '</div>'; // Close htmlView

        // JSON View
        echo '<div id="jsonView" ' . ($tab === 'json' ? '' : 'style="display:none;"') . '>';
        // The full analysis results are passed directly to the JSON view
        $json_str = json_encode($analysis_results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        echo '<pre style="background:#f3f4f6;padding:16px 16px 56px 16px;border-radius:8px;overflow:auto;max-height:320px;font-size:1rem;box-shadow:none;margin:0;">' . htmlspecialchars($json_str) . '</pre>';
        echo '</div>'; // Close jsonView

        // JavaScript for tab switching, copy, and download
        echo '<script>
            function switchTab(tabName) {
                document.getElementById("summaryTab").classList.remove("active");
                document.getElementById("htmlTab").classList.remove("active");
                document.getElementById("jsonTab").classList.remove("active");
                document.getElementById("summaryView").style.display = "none";
                document.getElementById("htmlView").style.display = "none";
                document.getElementById("jsonView").style.display = "none";

                if (tabName === "summary") {
                    document.getElementById("summaryTab").classList.add("active");
                    document.getElementById("summaryView").style.display = "block";
                } else if (tabName === "html") {
                    document.getElementById("htmlTab").classList.add("active");
                    document.getElementById("htmlView").style.display = "block";
                } else if (tabName === "json") {
                    document.getElementById("jsonTab").classList.add("active");
                    document.getElementById("jsonView").style.display = "block";
                }
            }

            document.getElementById("summaryTab").addEventListener("click", function(e) {
                e.preventDefault();
                switchTab("summary");
                history.pushState(null, "", "?domain=' . urlencode($domain) . '&tab=summary");
            });

            document.getElementById("htmlTab").addEventListener("click", function(e) {
                e.preventDefault();
                switchTab("html");
                history.pushState(null, "", "?domain=' . urlencode($domain) . '&tab=html");
            });

            document.getElementById("jsonTab").addEventListener("click", function(e) {
                e.preventDefault();
                switchTab("json");
                history.pushState(null, "", "?domain=' . urlencode($domain) . '&tab=json");
            });

            function copyJson() {
                const jsonOutput = document.querySelector("#jsonView pre");
                const textArea = document.createElement("textarea");
                textArea.value = jsonOutput.textContent;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand("copy");
                    console.log("JSON copied to clipboard!");
                } catch (err) {
                    console.error("Failed to copy JSON:", err);
                }
                document.body.removeChild(textArea);
            }

            function downloadJson() {
                const jsonOutput = document.querySelector("#jsonView pre");
                const jsonString = jsonOutput.textContent;
                const blob = new Blob([jsonString], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "gfw_test_results_' . urlencode($domain) . '.json";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                console.log("JSON downloaded successfully!");
            }

            // Set initial tab based on URL parameter
            window.onload = function() {
                const urlParams = new URLSearchParams(window.location.search);
                const initialTab = urlParams.get("tab") || "summary"; // Default to summary
                switchTab(initialTab);
            };
        </script>';

        echo '</div>'; // Close inner content div
    }
}
echo '</div>'; // Close container div
echo '</body></html>';
?>
