<?php
// Modern UI for Abuse Lookup Tool, inspired by reverse-mx-lookup
require_once __DIR__ . '/backend.php';

function render_header() {
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Abuse Lookup</title>';
    echo '<link rel="icon" type="image/png" href="/favicon.png">';
    echo '<style>
        body { font-family: Segoe UI, Arial, sans-serif; background: #f6f8fa; margin: 0; }
        .container { max-width: 1150px; margin: 30px auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); padding: 32px 32px 24px 32px; }
        h1 { font-size: 2rem; font-weight: 600; margin-bottom: 8px; }
        .desc { color: #555; margin-bottom: 24px; }
        .search-box { display: flex; gap: 12px; margin-bottom: 24px; }
        .search-box input { flex: 1; padding: 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }
        .search-box button { background: #7a0000; color: #fff; border: none; border-radius: 6px; padding: 0 28px; font-size: 1rem; font-weight: 600; cursor: pointer; box-shadow: 0 1px 2px rgba(0,0,0,0.04); transition: background 0.2s; }
        .search-box button:hover { background: #5a0000; }
        .tabs { display: flex; gap: 24px; border-bottom: 1px solid #e5e7eb; margin-bottom: 0; }
        .tab { padding: 12px 0; font-weight: 500; color: #222; cursor: pointer; border-bottom: 2px solid transparent; text-decoration: none; }
        .tab.active { border-bottom: 2px solid #7a0000; color: #7a0000; }
        .results-header { font-size: 1.2rem; font-weight: 500; margin: 24px 0 8px 0; }
        pre { background: #f3f4f6; padding: 16px; border-radius: 8px; overflow: auto; max-height: 320px; font-size: 1rem; box-shadow: none; margin: 0; }
    </style></head><body>';
}

function render_footer() {
    echo '</body></html>';
}

function render_main() {
    $query = isset($_GET['ip']) ? trim($_GET['ip']) : '';
    $tab = isset($_GET['tab']) ? $_GET['tab'] : 'html';
    $result = $query !== '' ? find_abuse_contact($query) : [];
    echo '<div class="container">';
    echo '<h1>Abuse Lookup</h1>';
    echo '<div class="desc">Find the abuse contact address for a domain name. This is where you would send complaints about spam originating from that domain.</div>';
    echo '<form class="search-box" method="get">';
    echo '<input type="text" name="ip" placeholder="Enter IP address or domain (e.g., 8.8.8.8 or example.com)" value="' . htmlspecialchars($query) . '" required />';
    echo '<button type="submit">Lookup</button>';
    echo '</form>';
    if ($query !== '') {
        $html_active = $tab === 'html' ? 'active' : '';
        $json_active = $tab === 'json' ? 'active' : '';
        $tab_query = htmlspecialchars($query);
        echo '<div class="tabs">';
        echo '<a href="?ip=' . urlencode($tab_query) . '&tab=html" class="tab ' . $html_active . '">HTML</a>';
        echo '<a href="?ip=' . urlencode($tab_query) . '&tab=json" class="tab ' . $json_active . '">JSON</a>';
        echo '</div>';
        echo '<div style="position:relative;box-shadow:0 2px 8px rgba(0,0,0,0.08);border-radius:0 0 12px 12px;background:#fff;padding:32px 32px 16px 32px;margin-bottom:32px;">';
        echo '<div class="results-header" style="margin-top:0;">Abuse lookup result for <b>' . htmlspecialchars($query) . '</b></div>';
        if ($tab === 'json') {
            $response = isset($result['error']) ? ['error' => $result['error']] : $result;
            $json = [
                "query" => ["tool" => "abuse-lookup", "input" => $query],
                "response" => [
                    "registrar" => $result['registrar'],
                    "whois_abuse" => $result['whois_abuse'],
                    "abuse_net" => $result['abuse_net']
                ]
            ];
            $json_str = json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            echo '<pre>' . htmlspecialchars($json_str) . '</pre>';
        } else {
            if (isset($result['error'])) {
                echo '<pre style="color:red;">' . htmlspecialchars($result['error']) . '</pre>';
            } else {
                $output = [];
                if ($result['registrar']) {
                    $output[] = 'Domain Registrar: ' . htmlspecialchars($result['registrar']);
                }
                if ($result['whois_abuse']) {
                    $output[] = 'Abuse contact from WHOIS: ' . htmlspecialchars($result['whois_abuse']);
                }
                if ($result['abuse_net']) {
                    $output[] = 'Abuse contact from abuse.net: ' . htmlspecialchars($result['abuse_net']);
                }

                if (empty($output)) {
                    echo '<p>Could not find specific abuse information. Displaying full WHOIS record:</p>';
                    echo '<pre>' . htmlspecialchars($result['full_record']) . '</pre>';
                } else {
                    echo '<pre>' . implode("\n", $output) . '</pre>';
                }
            }
        }
        echo '</div>';
    }
    echo '</div>';
}

render_header();
render_main();
render_footer();
?>
