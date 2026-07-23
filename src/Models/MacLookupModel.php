<?php
class MacLookupModel {
    private $mysqli;
    public function __construct($mysqli) {
        $this->mysqli = $mysqli;
    }
    public function lookupMac($mac) {
        if (!preg_match('/^([0-9A-Fa-f]{2}[:-]?){5}([0-9A-Fa-f]{2})$/', $mac) && 
            !preg_match('/^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$/', $mac) &&
            !preg_match('/^[0-9A-Fa-f]{12}$/', $mac)) {
            return ['error' => 'Invalid MAC address format (e.g., AA:BB:CC:DD:EE:FF or AABB.CCDD.EEFF)'];
        }
        $fullMac = strtoupper(preg_replace('/[^0-9A-Fa-f]/', '', $mac));
        $vendorData = $this->searchVendorsDatabase($fullMac);
        if (!$vendorData) {
            $vendorData = $this->searchLocalOUI($fullMac);
        }
        if ($vendorData) {
            return [
                'summary' => [
                    'MAC Address' => $mac,
                    'Vendor' => $vendorData['organization']
                ],
                'details' => [
                    'Matched Prefix' => $vendorData['assignment'],
                    'Vendor Name' => $vendorData['organization'],
                    'Address' => $vendorData['address'] ?? 'N/A',
                    'Private' => $vendorData['private'] ? 'Yes' : 'No',
                    'Block Type' => $vendorData['block_type'] ?? 'MA-L',
                    'Last Update' => $vendorData['last_update'] ?? date('Y-m-d')
                ],
                'source' => $vendorData['source'] ?? 'internal_registry'
            ];
        }
        return ['error' => 'No vendor information available for this MAC address in local database.'];
    }
    private function searchVendorsDatabase($fullMac) {
        if (!$this->mysqli) return null;
        for ($len = 12; $len >= 3; $len--) {
            $prefix = substr($fullMac, 0, $len);
            $sql = "SELECT vendorName, private, blockType, lastUpdate FROM vendors WHERE macPrefix = ? LIMIT 1";
            $stmt = $this->mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param('s', $prefix);
                $stmt->execute();
                $res = $stmt->get_result();
                if ($row = $res->fetch_assoc()) {
                    $stmt->close();
                    return [
                        'organization' => $row['vendorName'],
                        'assignment' => $prefix,
                        'private' => $row['private'],
                        'block_type' => $row['blockType'],
                        'last_update' => $row['lastUpdate'],
                        'source' => 'local_vendors_database'
                    ];
                }
                $stmt->close();
            }
        }
        return null;
    }
    private function searchLocalOUI($fullMac) {
        $file = __DIR__ . '/../Data/oui.csv';
        if (!file_exists($file)) return null;
        $handle = fopen($file, 'r');
        if (!$handle) return null;
        fgetcsv($handle);
        $bestMatch = null; $bestLen = 0;
        while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
            if (isset($data[1])) {
                $assign = strtoupper(trim($data[1]));
                if (strpos($fullMac, $assign) === 0 && strlen($assign) > $bestLen) {
                    $bestLen = strlen($assign);
                    $bestMatch = [
                        'organization' => $data[2] ?? 'Unknown',
                        'assignment' => $assign,
                        'address' => trim($data[3] ?? ''),
                        'private' => false,
                        'source' => 'local_oui_csv'
                    ];
                }
            }
        }
        fclose($handle);
        return $bestMatch;
    }
}