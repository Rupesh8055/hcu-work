#!/usr/bin/env node
const dns = require('dns');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const readline = require('readline');
const log = console;

const resolve = promisify(dns.resolve);
const reverse = promisify(dns.reverse);

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME'];
const OUTPUT_WIDTH = 50;
const DNS_TIMEOUT = 5000; // 5 seconds

// Create readline interface
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// Helper function for user input
function prompt(question) {
    return new Promise(resolve => {
        rl.question(question, resolve);
    });
}

function printBanner() {
    log.info(`
    ╔═════════════════════════════════╗
    ║            DNS REPORT           ║
    ╚═════════════════════════════════╝
    `);
}

function printSectionHeader(title) {
    log.info(`\n${'═'.repeat(30)}\n  ${title} \n${'═'.repeat(30)}`);
}

function isValidDomain(domain) {
    return /^(([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9-]*[a-z0-9])$/.test(domain);
}

async function resolveWithTimeout(domain, recordType) {
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('DNS query timeout')), DNS_TIMEOUT);
    });
    return Promise.race([resolve(domain, recordType), timeoutPromise]);
}

async function resolveRecord(domain, recordType) {
    try {
        log.info(`Querying ${recordType} record for ${domain}`);
        const answers = await resolveWithTimeout(domain, recordType);
        return answers;
    } catch (error) {
        if (error.code === 'ENODATA') {
            log.warn(`No ${recordType} record found for ${domain}`);
            return [];
        } else if (error.code === 'ENOTFOUND') {
            log.error(`Domain '${domain}' does not exist.`);
            throw new Error(`Domain '${domain}' does not exist.`);
        } else if (error.code === 'ETIMEOUT') {
            log.error(`Timeout while querying ${recordType} record for ${domain}`);
            throw new Error(`Timeout while querying ${recordType} record for ${domain}`);
        } else {
            log.error(`Error resolving ${recordType} record for ${domain}: ${error.message}`);
            return `ERROR: ${error.message}`;
        }
    }
}

async function getDnsRecords(domain) {
    let aRecordIp = null;
    let recordsFound = false;

    for (const recordType of RECORD_TYPES) {
        try {
            log.info(`[+] Querying ${recordType} Records...`);
            const results = await resolveRecord(domain, recordType);

            if (typeof results === 'string') {
                log.info(`[✗] ${recordType} Records: ${results}`.padEnd(OUTPUT_WIDTH));
            } else if (results.length === 0) {
                log.info(`[!] ${recordType} Records: No records found`.padEnd(OUTPUT_WIDTH));
            } else {
                log.info(`[✓] ${recordType} Records:`.padEnd(OUTPUT_WIDTH));
                results.forEach(result => {
                    log.info(`  • ${result}`);
                });
                recordsFound = true;
                if (recordType === 'A' && results.length > 0) {
                    aRecordIp = results[0];
                }
            }
        } catch (error) {
            log.error(`[✗] ${recordType} Records: Error - ${error.message}`.padEnd(OUTPUT_WIDTH));
        }
    }

    return { recordsFound, aRecordIp };
}

async function reverseDnsLookup(ipAddress) {
    printSectionHeader("REVERSE DNS LOOKUP");
    try {
        log.info("[+] Performing reverse DNS lookup...");
        const ptrRecords = await reverse(ipAddress);
        if (ptrRecords.length > 0) {
            log.info(`[✓] Reverse DNS (PTR): ${ptrRecords[0]}`.padEnd(OUTPUT_WIDTH));
        } else {
            log.info("[!] No PTR records found".padEnd(OUTPUT_WIDTH));
        }
        return true;
    } catch (error) {
        log.error(`[✗] Reverse DNS Lookup Failed: ${error.message}`.padEnd(OUTPUT_WIDTH));
        return false;
    }
}

async function saveReport(domain, aRecordIp) {
    const timestamp = moment().format("YYYYMMDD_HHmmss");
    const filename = `dns_report_${domain.replace(/\./g, '_')}_${timestamp}.txt`;
    log.info(`[+] Saving report to ${filename}...`);

    try {
        const stream = fs.createWriteStream(path.join(__dirname, filename));
        stream.write(`DNS REPORT FOR ${domain}\n`);
        stream.write(`Generated on: ${moment().format('YYYY-MM-DD HH:mm:ss')}\n`);
        stream.write("=" + "=".repeat(48) + "\n\n");

        for (const recordType of RECORD_TYPES) {
            const results = await resolveRecord(domain, recordType);
            stream.write(`${recordType} Records:\n`);
            if (typeof results === 'string') {
                stream.write(`  ${results}\n`);
            } else if (results.length === 0) {
                stream.write(`  No records found\n`);
            } else {
                results.forEach(item => {
                    stream.write(`  * ${item}\n`);
                });
            }
            stream.write("\n");
        }

        if (aRecordIp) {
            try {
                const ptrRecords = await reverse(aRecordIp);
                stream.write("REVERSE DNS LOOKUP:\n");
                stream.write(`IP Address (A Record): ${aRecordIp}\n`);
                if (ptrRecords.length > 0) {
                    stream.write(`Reverse DNS (PTR): ${ptrRecords[0]}\n`);
                } else {
                    stream.write(`No PTR records found\n`);
                }
            } catch (error) {
                stream.write(`Reverse DNS Lookup Failed: ${error.message}\n`);
            }
        }

        try {
            stream.end();
            log.info(`[✓] Report saved successfully to: ${filename}`);
        } catch (error) {
            log.error(`[✗] Failed to close report file: ${error.message}`);
        }
    } catch (error) {
        log.error(`[✗] Failed to save report: ${error.message}`.padEnd(OUTPUT_WIDTH));
    }
}

function exitMessage() {
    log.info("\nThank you for using the DNS Report Tool. Goodbye!");
    rl.close();
    process.exit(0);
}

async function main() {
    printBanner();
    while (true) {
        const userDomain = (await prompt("\n➤ Enter domain (or 'exit' to quit): ")).trim().toLowerCase();
        if (userDomain === 'exit') {
            exitMessage();
            break;
        }
        if (!userDomain) {
            log.info("[!] Please enter a valid domain name.");
            continue;
        }
        if (!isValidDomain(userDomain)) {
            log.info("[!] Invalid domain name format.");
            continue;
        }

        printSectionHeader(`DNS REPORT FOR ${userDomain}`);
        log.info(`[i] Scan started at: ${moment().format('YYYY-MM-DD HH:mm:ss')}`);

        try {
            const { recordsFound, aRecordIp } = await getDnsRecords(userDomain);

            if (recordsFound && aRecordIp) {
                await reverseDnsLookup(aRecordIp);
            }

            if (recordsFound) {
                const saveOption = (await prompt("\n➤ Would you like to save this report to a file? (y/n): ")).trim().toLowerCase();
                if (saveOption === 'y') {
                    await saveReport(userDomain, aRecordIp);
                }
            }
        } catch (error) {
            log.error(`[✗] Error processing domain: ${error.message}`);
        }
    }
}

// Handle Ctrl+C gracefully
process.on('SIGINT', () => {
    exitMessage();
});

main().catch(error => {
    log.error(`[✗] An unexpected error occurred: ${error.message}`);
    rl.close();
    process.exit(1);
});