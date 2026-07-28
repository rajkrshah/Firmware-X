class EncryptionAnalyzer {
    constructor() {
        this.entropy = 0;
        this.findings = [];
        this.assessment = "";
        this.status = "Plaintext";
        this.statusClass = "sev-info";
    }

    async analyze(data) {
        this.findings = [];
        
        // 1. Calculate Shannon Entropy
        this.entropy = this.calculateEntropy(data);
        
        // 2. Scan for Cryptographic Signatures
        this.scanSignatures(data);
        
        // 3. Detect Weak Encryption (e.g. Repeating XOR keys)
        this.detectWeakXOR(data);
        
        // 4. Formulate Assessment
        this.formulateAssessment();
        
        return {
            entropy: this.entropy,
            status: this.status,
            statusClass: this.statusClass,
            assessment: this.assessment,
            findings: this.findings
        };
    }

    calculateEntropy(data) {
        const frequencies = new Array(256).fill(0);
        for (let i = 0; i < data.length; i++) {
            frequencies[data[i]]++;
        }

        let entropy = 0;
        const length = data.length;
        for (let i = 0; i < 256; i++) {
            if (frequencies[i] > 0) {
                const p = frequencies[i] / length;
                entropy -= p * Math.log2(p);
            }
        }
        return entropy;
    }

    scanSignatures(data) {
        // Convert first 10KB to string for simple magic byte searching
        let scanLimit = Math.min(data.length, 10240);
        let headerStr = "";
        for(let i = 0; i < scanLimit; i++) {
            headerStr += String.fromCharCode(data[i]);
        }

        const signatures = [
            { magic: "Salted__", name: "OpenSSL Encrypted Data", desc: "Detected OpenSSL standard 'Salted__' magic bytes." },
            { magic: "U-Boot", name: "U-Boot Image", desc: "Found U-Boot header. Firmware might be packed rather than fully encrypted." },
            { magic: "PK\x03\x04", name: "ZIP Archive / APK", desc: "Detected ZIP magic bytes. Firmware is an archive." },
            { magic: "\x1F\x8B", name: "GZIP Compressed", desc: "Detected GZIP magic bytes. Payload is compressed, inflating may reveal plaintext." },
            { magic: "SqSh", name: "SquashFS Filesystem", desc: "Detected SquashFS. Standard filesystem compression in use." }
        ];

        signatures.forEach(sig => {
            let offset = headerStr.indexOf(sig.magic);
            if (offset !== -1) {
                this.findings.push({
                    type: "Known Signature",
                    name: sig.name,
                    description: sig.desc,
                    offset: `0x${offset.toString(16)}`
                });
            }
        });
        
        // Detect AES S-Box presence (crude check for AES routines)
        // Usually, Rijndael S-box is 256 bytes starting with 0x63, 0x7c, 0x77, 0x7b
        for (let i = 0; i < data.length - 4; i++) {
            if (data[i] === 0x63 && data[i+1] === 0x7c && data[i+2] === 0x77 && data[i+3] === 0x7b) {
                this.findings.push({
                    type: "Cryptographic Constant",
                    name: "AES S-Box Detected",
                    description: "Detected standard Rijndael (AES) S-Box constants. The firmware performs AES operations.",
                    offset: `0x${i.toString(16)}`
                });
                break; // Only report once
            }
        }
    }

    detectWeakXOR(data) {
        // Look for common 4-byte repeating patterns that indicate a weak XOR mask
        // Many firmwares are padded with 0x00 or 0xFF. If XOR'd, the key repeats in the padding.
        
        if (data.length < 1024) return;
        
        // Scan the last 512 bytes (often padding)
        let paddingStart = data.length - 512;
        let patternCount = 0;
        let potentialKey = [];
        
        for (let i = paddingStart; i < data.length - 8; i+=4) {
            let v1 = data[i] | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24);
            let v2 = data[i+4] | (data[i+5]<<8) | (data[i+6]<<16) | (data[i+7]<<24);
            if (v1 === v2 && v1 !== 0 && v1 !== -1) {
                patternCount++;
                potentialKey = [data[i], data[i+1], data[i+2], data[i+3]];
            }
        }
        
        if (patternCount > 10) {
            let keyHex = potentialKey.map(b => b.toString(16).padStart(2, '0')).join('');
            this.findings.push({
                type: "Weak Encryption",
                name: "Repeating XOR Key Detected",
                description: `Detected highly repetitive 4-byte pattern (Likely XOR padding). Potential Key: 0x${keyHex}`,
                offset: "EOF Padding"
            });
        }
    }

    formulateAssessment() {
        let isEncrypted = false;
        let isPacked = false;
        let isWeak = false;

        this.findings.forEach(f => {
            if (f.name === "Repeating XOR Key Detected") isWeak = true;
            if (f.type === "Known Signature") isPacked = true;
            if (f.name === "OpenSSL Encrypted Data") isEncrypted = true;
        });

        if (this.entropy > 7.9) {
            if (isWeak) {
                this.status = "Weakly Encrypted";
                this.statusClass = "sev-high";
                this.assessment = "The firmware exhibits near-perfect entropy (indicating encryption), but a repeating XOR key was extracted from the padding. <b>Decryption Feasibility: HIGH.</b> The payload can be easily decrypted by applying the extracted XOR mask over the entire binary.";
            } else if (isPacked) {
                this.status = "Compressed / Packed";
                this.statusClass = "sev-medium";
                this.assessment = "High entropy is present, but known compression/filesystem headers were detected. <b>Decryption Feasibility: N/A (Compressed).</b> Extract the filesystem using standard tools (e.g. binwalk, unsquashfs).";
            } else {
                this.status = "Strongly Encrypted";
                this.statusClass = "sev-critical";
                this.assessment = "The firmware has extremely high entropy (> 7.9 bits/byte) with no recognizable structures, headers, or weak patterns. This suggests the use of a strong symmetric cipher (like AES-CBC or ChaCha20). <b>Decryption Feasibility: VERY LOW.</b> You will need to extract the decryption key via hardware side-channels, bootloader extraction, or companion-app reversing.";
            }
        } else if (this.entropy > 6.5) {
            this.status = "Partially Obfuscated";
            this.statusClass = "sev-medium";
            this.assessment = "Moderate entropy suggests the firmware is only partially encrypted, obfuscated, or uses a weak encoding mechanism. Code segments might be packed while resources remain plaintext. <b>Feasibility: MEDIUM.</b>";
        } else {
            this.status = "Plaintext";
            this.statusClass = "sev-info";
            this.assessment = "Low entropy (< 6.5 bits/byte) indicates the firmware is largely unencrypted. Instructions and strings should be highly visible in the Disassembly and Strings views. <b>Decryption Feasibility: N/A (Already Plaintext).</b>";
        }
    }
}

// Make available globally
window.EncryptionAnalyzer = EncryptionAnalyzer;
