const express = require('express');
const fetch = require('node-fetch'); // Ensure node-fetch is installed (npm install node-fetch@2 or @3 if ESM)

const app = express();
const port = 3000;

app.use(express.static('public'));

async function fetchWithRetries(url, options = {}, retries = 3, initialDelay = 1000) {
    const defaultHeaders = {
        'User-Agent': 'ASNLookupTool/1.0 (+https://yourwebsite.com/contact or your_email@example.com)'
    };
    const combinedOptions = {
        ...options,
        headers: { ...defaultHeaders, ...options.headers }
    };

    for (let i = 0; i < retries; i++) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000); // 15-second timeout for each attempt

        try {
            const response = await fetch(url, { signal: controller.signal, ...combinedOptions });
            clearTimeout(timeout);

            if (response.ok) {
                return response;
            } else if (response.status === 429 || response.status >= 500 || response.status === 408) {
                console.warn(`Retryable error ${response.status} for ${url}. Retrying...`);
            } else {
                // For other client errors (4xx), don't retry.
                const errorData = await response.json().catch(() => ({}));
                const errorMessage = errorData.title || `API returned status ${response.status} ${response.statusText}`;
                throw new Error(`Non-retryable API error: ${errorMessage}`);
            }
        } catch (error) {
            clearTimeout(timeout);
            if (error.code === 'ECONNRESET' || error.name === 'AbortError' || error.name === 'FetchError') {
                console.warn(`Attempt ${i + 1}/${retries} failed for ${url} with error: ${error.message}. Retrying...`);
            } else {
                throw error;
            }
        }

        // Exponential backoff
        const delay = initialDelay * Math.pow(2, i);
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    throw new Error(`Failed to fetch ${url} after ${retries} attempts.`);
}

app.get('/api/lookup', async (req, res) => {
    const asnQuery = req.query.asn;
    if (!asnQuery) {
        return res.status(400).json({ Error: "ASN query parameter is missing." });
    }
    try {
        const asnInfo = await deepLookupASN(asnQuery);
        res.json(asnInfo);
    } catch (error) {
        console.error("Server-side lookup error:", error);
        if (error.message.startsWith("Failed to fetch") || error.message.startsWith("Non-retryable API error")) {
            res.status(502).json({ Error: `External API error: ${error.message}` });
        } else {
            res.status(500).json({ Error: "An internal server error occurred." });
        }
    }
});

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});

async function deepLookupASN(query) {
    const asnNumber = query.replace(/\D/g, '');
    if (!asnNumber) {
        return { Error: "Invalid ASN format. Please enter a valid ASN (e.g., AS15169)." };
    }
    
    try {
        let currentUrl = `https://rdap.arin.net/bootstrap/autnum/${asnNumber}`;
        let finalData;

        // Initial fetch from ARIN, which acts as a bootstrap/referral service
        let initialResponse = await fetchWithRetries(currentUrl);
        let initialResponseData = await initialResponse.json();

        // Check for a referral link and follow it to the authoritative RIR
        const referralLink = initialResponseData.links?.find(
            l => l.rel === 'self' && l.type === 'application/rdap+json' && l.href && l.href !== currentUrl
        );

        if (referralLink) {
            currentUrl = referralLink.href;
            let referralResponse = await fetchWithRetries(currentUrl);
            finalData = await referralResponse.json();
        } else {
            finalData = initialResponseData;
        }

        const entityUrls = new Set();
        finalData.entities?.forEach(entity => {
            const selfLink = entity.links?.find(l => l.rel === 'self')?.href;
            if (selfLink) {
                entityUrls.add(selfLink);
            }
        });

        const entitiesByHandle = new Map();
        if (entityUrls.size > 0) {
            const entityPromises = Array.from(entityUrls).map(url =>
                fetchWithRetries(url)
                    .then(res => res.json())
                    .catch(e => {
                        console.warn(`Failed to fetch detailed entity from ${url}:`, e.message);
                        return null; // Return null if fetching a specific entity fails
                    })
            );
            const detailedEntities = (await Promise.all(entityPromises)).filter(Boolean);
            detailedEntities.forEach(e => entitiesByHandle.set(e.handle, e));
        }

        return parseRdaResponse(finalData, entitiesByHandle);

    } catch (error) {
        if (error.message.includes('Invalid ASN format')) {
            return { Error: error.message };
        }
        console.error("RDAP API Deep Fetch Error:", error.message);
        return { Error: `Failed to fetch data from the RDAP API: ${error.message.split(":")[0]}. Please try again or check the ASN.` };
    }
}

function parseRdaResponse(mainData, entitiesByHandle) {
    const result = {};

    const findVcardProp = (vcard, propName) => {
        if (!vcard || vcard[0] !== 'vcard' || !Array.isArray(vcard[1])) return null;
        const prop = vcard[1].find(p => p[0] === propName);
        if (!prop) return null;
        return typeof prop[3] === 'string' ? prop[3] : Array.isArray(prop[3]) ? prop[3].join(', ') : null;
    };

    const fillContactBlock = (entity, prefix) => {
        if (!entity) return;
        const vcard = entity.vcardArray;
        result[`${prefix}_Handle`] = entity.handle;
        result[`${prefix}_Name`] = findVcardProp(vcard, 'fn') || entity.handle;
        const phone = findVcardProp(vcard, 'tel');
        const email = findVcardProp(vcard, 'email');
        if (phone) result[`${prefix}_Phone`] = phone.replace('tel:', '');
        if (email) result[`${prefix}_Email`] = email.replace('mailto:', '');
    };

    result['ASN'] = mainData.handle;
    result['AS_Name'] = mainData.name;
    result['Country'] = mainData.country;

    const regDate = mainData.events?.find(e => e.eventAction === 'registration');
    const lastDate = mainData.events?.find(e => e.eventAction === 'last changed');
    if (regDate?.eventDate) result['Registration_Date'] = new Date(regDate.eventDate).toISOString().split('T')[0];
    if (lastDate?.eventDate) result['Last_Updated'] = new Date(lastDate.eventDate).toISOString().split('T')[0];

    mainData.entities?.forEach(entitySummary => {
        const handle = entitySummary.handle;
        const roles = entitySummary.roles || [];
        const detailedEntity = entitiesByHandle.get(handle);

        if (detailedEntity) {
            if (roles.includes('registrant')) {
                result['Organization_Name'] = findVcardProp(detailedEntity.vcardArray, 'fn') || detailedEntity.handle;
                result['Organization_ID'] = detailedEntity.handle;
                const adrProp = detailedEntity.vcardArray?.[1].find(p => p[0] === 'adr');
                if (adrProp && Array.isArray(adrProp[3])) {
                    result['Address'] = adrProp[3].slice(1).filter(part => part).join('\n');
                }
            }
            if (roles.includes('technical')) fillContactBlock(detailedEntity, 'Tech_Contact');
            if (roles.includes('abuse')) fillContactBlock(detailedEntity, 'Abuse_Contact');
            if (roles.includes('administrative')) fillContactBlock(detailedEntity, 'Admin_Contact');
            if (roles.includes('routing')) fillContactBlock(detailedEntity, 'Routing_Contact');
        }
    });

    const fieldOrder = [
        'ASN', 'AS_Name', 'Country', 'Registration_Date', 'Last_Updated',
        'Organization_Name', 'Organization_ID', 'Address',
        'Routing_Contact_Handle', 'Routing_Contact_Name', 'Routing_Contact_Phone', 'Routing_Contact_Email',
        'Abuse_Contact_Handle', 'Abuse_Contact_Name', 'Abuse_Contact_Phone', 'Abuse_Contact_Email',
        'Tech_Contact_Handle', 'Tech_Contact_Name', 'Tech_Contact_Phone', 'Tech_Contact_Email',
        'Admin_Contact_Handle', 'Admin_Contact_Name', 'Admin_Contact_Phone', 'Admin_Contact_Email'
    ];
    
    const orderedResult = {};
    for (const field of fieldOrder) {
        if (result[field]) orderedResult[field] = result[field];
    }
    return orderedResult;
}
