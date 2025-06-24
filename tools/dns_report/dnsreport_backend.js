// Required modules
const dns = require('dns');
const util = require('util');
const readline = require('readline');

// List of public DNS servers to check against
const dnsServers = [
    "8.8.8.8",      // Google
    "8.8.4.4",      // Google secondary
    "1.1.1.1",      // Cloudflare
    "208.67.222.222",  // OpenDNS
    "9.9.9.9",      // Quad9
    "8.26.56.26",   // Comodo
    "4.2.2.1"       // Level3
];

function printBanner() {
    const banner = `
╔══════════════════════════════════════════════════╗
║              DNS PROPAGATION CHECKER             ║
║        Check DNS resolution across servers       ║
╚══════════════════════════════════════════════════╝
`;
    console.log(banner);
}

async function checkDnsPropagation(domain, recordType = "A") {
    console.log(`\n[+] Checking DNS Propagation for: ${domain} (${recordType})`);
    console.log("=".repeat(60));
    
    const results = {};
    let consistent = true;
    let previousRecords = null;
    
    for (const server of dnsServers) {
        // Create a custom resolver for this server
        const resolver = new dns.Resolver();
        resolver.setServers([server]);
        
        // Promisify the resolve method specifically for this resolver instance
        const resolveWithServer = util.promisify(resolver.resolve.bind(resolver));
        
        try {
            const timeoutPromise = new Promise((_, reject) =>   //Timeout for the DNS query.
                setTimeout(() => reject(new Error('Timeout')), 5000)
            );
            
            // Race between the DNS query and the timeout
            const answer = await Promise.race([
                resolveWithServer(domain, recordType),
                timeoutPromise
            ]);
            
            const records = answer.map(r => r.toString());
            results[server] = records;
            
            if (previousRecords === null) {   // Checks if records are consistent across servers.
                previousRecords = [...records].sort();
            } else {
                const sortedRecords = [...records].sort();
                if (JSON.stringify(previousRecords) !== JSON.stringify(sortedRecords)) {
                    consistent = false;
                }
            }
            
            console.log(`[✓] ${server}: ${records.join(', ')}`);
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ENODATA' || error.message.includes('NXDOMAIN')) {
                results[server] = "NXDOMAIN";
                console.log(`[!] ${server}: Domain does not exist (NXDOMAIN)`);
                consistent = false;
            } else if (error.message === 'Timeout' || error.code === 'ETIMEDOUT') {
                results[server] = "Timeout";
                console.log(`[!] ${server}: Timeout`);
            } else if (error.code === 'ENODATA') {
                results[server] = "No answer";
                console.log(`[!] ${server}: No answer`);
                consistent = false;
            } else {
                results[server] = `Error: ${error.message}`;
                console.log(`[!] ${server}: Error - ${error.message}`);
                consistent = false;
            }
        }
    }
    
    console.log("\n" + "=".repeat(60));
    if (consistent && previousRecords !== null) {
        console.log(`[✓] DNS Propagation Status: COMPLETE`);
        console.log(`[✓] All servers returned the same ${recordType} records for ${domain}`);
    } else {
        console.log(`[!] DNS Propagation Status: INCOMPLETE`);
        console.log(`[!] Different DNS servers returned different results for ${domain}`);
    }
    
    return results;
}

async function main() {
    printBanner();
    
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    const question = (query) => new Promise((resolve) => rl.question(query, resolve));
    
    try {
        while (true) {
            const domainToCheck = (await question("\nEnter domain name (or 'exit' to quit): ")).trim();
            if (domainToCheck.toLowerCase() === 'exit') {
                console.log("\nThank you for using DNS Propagation Checker!");
                break;
            }
            
            const recordType = ((await question("Enter record type (A, CNAME, MX, TXT, etc.) [default: A]: ")).trim().toUpperCase() || "A");
            
            // Validating domain format.
            if (!domainToCheck || !domainToCheck.includes('.')) {
                console.log("[!] Invalid domain name. Please enter a valid domain (e.g., example.com)");
                continue;
            }
            
            console.log("\n[+] Starting DNS propagation check...");
            await checkDnsPropagation(domainToCheck, recordType);
            
            const checkAgain = (await question("\nCheck another domain? (y/n): ")).trim().toLowerCase();
            if (checkAgain !== 'y') {
                console.log("\nThank you for using DNS Propagation Checker!");
                break;
            }
        }
    } catch (error) {
        console.log(`\n[!] An error occurred: ${error.message}`);
    } finally {
        rl.close();
    }
}

// Runs the script if it's executed directly.
if (require.main === module) {
    main().catch(error => {
        console.error(`\n[!] An unexpected error occurred: ${error.message}`);
        process.exit(1);
    });
}

module.exports = {
    checkDnsPropagation
}; 