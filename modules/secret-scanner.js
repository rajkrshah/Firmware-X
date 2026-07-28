const fs = require('fs');

const RULES = [
    {
        name: 'AWS Access Key',
        regex: /\b(AKIA[0-9A-Z]{16})\b/g,
        severity: 'critical',
        description: 'Hardcoded AWS API Key. Could allow cloud account takeover.'
    },
    {
        name: 'RSA Private Key',
        regex: /(-----BEGIN RSA PRIVATE KEY-----)/g,
        severity: 'critical',
        description: 'Hardcoded RSA Private Key. Often used for firmware signing or SSH auth.'
    },
    {
        name: 'Generic Private Key',
        regex: /(-----BEGIN PRIVATE KEY-----)/g,
        severity: 'critical',
        description: 'Hardcoded Private Key (EC/PKCS8).'
    },
    {
        name: 'OpenSSH Private Key',
        regex: /(-----BEGIN OPENSSH PRIVATE KEY-----)/g,
        severity: 'critical',
        description: 'Hardcoded SSH Private Key.'
    },
    {
        name: 'Root Password Hash',
        regex: /\b(root:\$[156y]\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{20,86})\b/g,
        severity: 'critical',
        description: 'Hardcoded Linux root password hash (found in /etc/shadow dumps).'
    },
    {
        name: 'Hardcoded Bearer Token',
        regex: /(?:Bearer\s+)([A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,})/g,
        severity: 'high',
        description: 'Hardcoded JWT Bearer Token.'
    },
    {
        name: 'GitHub Personal Access Token',
        regex: /\b(ghp_[a-zA-Z0-9]{36})\b/g,
        severity: 'critical',
        description: 'GitHub PAT token. Could allow repo access.'
    }
];

class SecretScanner {
    /**
     * Scans a file on disk for secrets using a chunked, overlapping read approach.
     * @param {string} filePath - Path to the firmware file
     * @returns {Promise<Array>} - Array of vulnerabilities found
     */
    static async scanFile(filePath) {
        return new Promise((resolve, reject) => {
            const stream = fs.createReadStream(filePath);
            const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
            const OVERLAP = 4096; // Overlap to catch secrets crossing chunk boundaries
            
            let previousChunk = Buffer.alloc(0);
            let globalOffset = 0;
            const findings = [];
            const seenOffsets = new Set();
            
            stream.on('data', (chunk) => {
                const searchBuffer = Buffer.concat([previousChunk, chunk]);
                // Use latin1 to map bytes 1:1 to characters without UTF-8 corruption
                const searchString = searchBuffer.toString('latin1');
                
                for (const rule of RULES) {
                    let match;
                    rule.regex.lastIndex = 0;
                    while ((match = rule.regex.exec(searchString)) !== null) {
                        const absoluteOffset = globalOffset - previousChunk.length + match.index;
                        
                        if (seenOffsets.has(absoluteOffset)) continue;
                        seenOffsets.add(absoluteOffset);
                        
                        const contextStart = Math.max(0, match.index - 20);
                        const contextEnd = Math.min(searchString.length, match.index + match[0].length + 20);
                        let context = searchString.substring(contextStart, contextEnd);
                        context = context.replace(/[^ -~]/g, '.');
                        
                        findings.push({
                            type: rule.name,
                            severity: rule.severity,
                            offset: `0x${absoluteOffset.toString(16).toUpperCase()}`,
                            description: rule.description,
                            context: context,
                            secret: match[1]
                        });
                    }
                }
                
                globalOffset += chunk.length;
                if (chunk.length >= OVERLAP) {
                    previousChunk = chunk.subarray(chunk.length - OVERLAP);
                } else {
                    previousChunk = Buffer.concat([previousChunk, chunk]).subarray(-OVERLAP);
                }
            });
            
            stream.on('end', () => resolve(findings));
            stream.on('error', reject);
        });
    }
}

module.exports = SecretScanner;
