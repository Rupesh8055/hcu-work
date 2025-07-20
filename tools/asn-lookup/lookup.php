<?php
// Set headers for JSON response and disable caching.
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// --- Main Execution Block ---

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['Error' => 'Method Not Allowed. Please use GET.']);
    exit;
}

$asnQuery = trim($_GET['asn'] ?? '');
if (empty($asnQuery)) {
    http_response_code(400);
    echo json_encode(['Error' => 'ASN query parameter is missing.']);
    exit;
}

try {
    $asnInfo = deepLookupASN($asnQuery);
    echo json_encode($asnInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} catch (Exception $e) {
    if (strpos($e->getMessage(), 'Failed to fetch') !== false || strpos($e->getMessage(), 'RDAP API') !== false) {
        http_response_code(502); // Bad Gateway
    } else {
        http_response_code(500); // Internal Server Error
    }
    error_log("ASN Lookup Error: " . $e->getMessage());
    echo json_encode(['Error' => 'An external or server error occurred: ' . $e->getMessage()]);
}

exit;


// --- Function Definitions ---

/**
 * Fetches a URL with retry logic and robust cURL options.
 * @throws Exception On fetch failure after all retries.
 */
function fetchWithRetries(string $url, int $retries = 3): ?array {
    // Use a standard browser User-Agent to avoid being blocked.
    $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36';
    
    // Add standard browser headers to make the request look less like a script.
    $headers = [
        'User-Agent: ' . $userAgent,
        'Accept: application/rdap+json,application/json;q=0.9,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.5',
        'Accept-Encoding: gzip, deflate, br',
        'Connection: keep-alive',
    ];

    for ($i = 0; $i < $retries; $i++) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        // --- Options to improve connection reliability ---
        curl_setopt($ch, CURLOPT_ENCODING, ""); // Handle gzip, deflate, etc. automatically.
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        // Force a modern, widely-supported TLS version to prevent handshake issues.
        curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2); 
        // Prefer IPv4, which can sometimes be more stable or less restricted.
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        // --- End of new options ---
        
        $response = curl_exec($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($response !== false && $http_status >= 200 && $http_status < 300) {
            return json_decode($response, true) ?: [];
        }
        
        if ($http_status === 429 || $http_status === 408 || $http_status >= 500) {
            usleep(1000 * 1000 * pow(2, $i)); // Exponential backoff
            continue;
        }
        if ($curl_error) {
            throw new Exception("Network error fetching {$url}: " . $curl_error);
        }
    }
    throw new Exception("Failed to fetch {$url} after {$retries} attempts. Last status: {$http_status}.");
}

/**
 * Performs a deep lookup by following RDAP referrals.
 */
function deepLookupASN(string $query): array {
    $asnNumber = preg_replace('/\D/', '', $query);
    if (empty($asnNumber)) {
        return ['Error' => 'Invalid ASN format. Please enter a valid ASN (e.g., AS15169).'];
    }

    // Use a reliable public RDAP bootstrap server like ARIN's.
    $bootstrapUrl = "https://rdap.arin.net/bootstrap/autnum/{$asnNumber}";
    $initialData = fetchWithRetries($bootstrapUrl);
    
    // Follow the referral link to the authoritative RDAP server.
    $finalData = $initialData;
    if (isset($initialData['links'])) {
        foreach ($initialData['links'] as $link) {
            if (($link['rel'] ?? '') === 'self' && !empty($link['href'])) {
                $finalData = fetchWithRetries($link['href']);
                break;
            }
        }
    }

    if (empty($finalData) || (isset($finalData['objectClassName']) && $finalData['objectClassName'] === 'rdapNotice')) {
        $errorTitle = $finalData['title'] ?? "ASN Not Found";
        $errorDesc = $finalData['description'][0] ?? "The ASN could not be found or is not allocated.";
        return ['Error' => "{$errorTitle}: {$errorDesc}"];
    }

    // Fetch full details for all associated entities.
    $entitiesByHandle = [];
    if (!empty($finalData['entities'])) {
        foreach ($finalData['entities'] as $entityStub) {
            if (empty($entityStub['handle']) || isset($entitiesByHandle[$entityStub['handle']])) continue;
            
            $entitySelfLink = null;
            if (!empty($entityStub['links'])) {
                foreach($entityStub['links'] as $link) {
                    if(($link['rel'] ?? '') === 'self' && !empty($link['href'])) {
                        $entitySelfLink = $link['href'];
                        break;
                    }
                }
            }

            if($entitySelfLink) {
                try {
                    $entityData = fetchWithRetries($entitySelfLink, 2);
                    if (isset($entityData['handle'])) {
                        $entitiesByHandle[$entityData['handle']] = $entityData;
                    }
                } catch (Exception $e) {
                    error_log("Could not fetch entity {$entityStub['handle']}: " . $e->getMessage());
                }
            }
        }
    }
    
    return parseRdapResponse($finalData, $entitiesByHandle);
}

/**
 * Parses the RDAP JSON responses into a structured, ordered array for display.
 */
function parseRdapResponse(array $mainData, array $entitiesByHandle): array {
    $result = [];

    $findVcardProp = function($vcard, $propName) {
        if (empty($vcard) || $vcard[0] !== 'vcard' || !is_array($vcard[1])) return null;
        foreach($vcard[1] as $prop) {
            if ($prop[0] === $propName) {
                return is_array($prop[3]) ? implode(', ', $prop[3]) : $prop[3];
            }
        }
        return null;
    };

    $fillContactBlock = function($entity, $prefix) use (&$result, $findVcardProp) {
        if (!$entity) return;
        $vcard = $entity['vcardArray'] ?? null;
        $result["{$prefix}_Handle"] = $entity['handle'] ?? null;
        $result["{$prefix}_Name"] = $findVcardProp($vcard, 'fn') ?: ($entity['handle'] ?? null);
        $phone = $findVcardProp($vcard, 'tel');
        $email = $findVcardProp($vcard, 'email');
        if ($phone) $result["{$prefix}_Phone"] = str_replace('tel:', '', $phone);
        if ($email) $result["{$prefix}_Email"] = str_replace('mailto:', '', $email);
    };

    $result['ASN'] = $mainData['handle'] ?? null;
    $result['AS_Name'] = $mainData['name'] ?? null;
    $result['Country'] = $mainData['country'] ?? null;

    if (!empty($mainData['events'])) {
        foreach($mainData['events'] as $event) {
            $action = $event['eventAction'] ?? '';
            $date = $event['eventDate'] ?? '';
            if ($date && $action === 'registration') $result['Registration_Date'] = substr($date, 0, 10);
            if ($date && $action === 'last changed') $result['Last_Updated'] = substr($date, 0, 10);
        }
    }
    
    if (!empty($mainData['entities'])) {
        foreach($mainData['entities'] as $entitySummary) {
            $handle = $entitySummary['handle'] ?? null;
            $roles = $entitySummary['roles'] ?? [];
            $detailedEntity = $entitiesByHandle[$handle] ?? null;

            if ($detailedEntity) {
                if (in_array('registrant', $roles)) {
                    $vcard = $detailedEntity['vcardArray'] ?? null;
                    $result['Organization_Name'] = $findVcardProp($vcard, 'fn') ?: ($detailedEntity['handle'] ?? null);
                    $result['Organization_ID'] = $detailedEntity['handle'] ?? null;
                    
                    if (isset($vcard[1])) {
                        foreach($vcard[1] as $prop) {
                            if ($prop[0] === 'adr' && is_array($prop[3])) {
                                $addressParts = array_filter(array_slice($prop[3], 0, 7));
                                $result['Address'] = implode("\n", $addressParts);
                                break;
                            }
                        }
                    }
                }
                if (in_array('technical', $roles)) $fillContactBlock($detailedEntity, 'Tech_Contact');
                if (in_array('abuse', $roles)) $fillContactBlock($detailedEntity, 'Abuse_Contact');
                if (in_array('administrative', $roles)) $fillContactBlock($detailedEntity, 'Admin_Contact');
                if (in_array('routing', $roles)) $fillContactBlock($detailedEntity, 'Routing_Contact');
            }
        }
    }

    $fieldOrder = [
        'ASN', 'AS_Name', 'Country', 'Registration_Date', 'Last_Updated',
        'Organization_Name', 'Organization_ID', 'Address',
        'Routing_Contact_Handle', 'Routing_Contact_Name', 'Routing_Contact_Phone', 'Routing_Contact_Email',
        'Abuse_Contact_Handle', 'Abuse_Contact_Name', 'Abuse_Contact_Phone', 'Abuse_Contact_Email',
        'Tech_Contact_Handle', 'Tech_Contact_Name', 'Tech_Contact_Phone', 'Tech_Contact_Email',
        'Admin_Contact_Handle', 'Admin_Contact_Name', 'Admin_Contact_Phone', 'Admin_Contact_Email'
    ];
    
    $orderedResult = [];
    foreach ($fieldOrder as $field) {
        if (!empty($result[$field])) {
            $orderedResult[$field] = $result[$field];
        }
    }
    return $orderedResult;
}