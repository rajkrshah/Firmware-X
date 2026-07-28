(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.DecryptionEngine = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @class DecryptionEngine
     * Provides symmetric decryption and cipher functions.
     */
    const DecryptionEngine = {
        /**
         * XOR decryption.
         * @param {Uint8Array} uint8Array - Data to decrypt.
         * @param {number|Uint8Array} key - XOR key.
         * @returns {Uint8Array} Decrypted data.
         */
        xorDecrypt(uint8Array, key) {
            if (!(uint8Array instanceof Uint8Array)) throw new Error("Data must be Uint8Array");
            
            const result = new Uint8Array(uint8Array.length);
            
            if (typeof key === 'number') {
                for (let i = 0; i < uint8Array.length; i++) {
                    result[i] = uint8Array[i] ^ key;
                }
            } else if (key instanceof Uint8Array) {
                if (key.length === 0) return uint8Array.slice();
                for (let i = 0; i < uint8Array.length; i++) {
                    result[i] = uint8Array[i] ^ key[i % key.length];
                }
            } else {
                throw new Error("Invalid key format");
            }
            
            return result;
        },

        xorBruteForce(uint8Array, options = {}) {
            const sampleSize = options.sampleSize || 1024;
            const topN = options.topN || 5;
            const dataToTest = uint8Array.subarray(0, Math.min(sampleSize, uint8Array.length));
            
            const results = [];
            
            for (let key = 0; key < 256; key++) {
                let printable = 0;
                let previewStr = '';
                
                for (let i = 0; i < dataToTest.length; i++) {
                    const dec = dataToTest[i] ^ key;
                    if (dec >= 32 && dec <= 126) {
                        printable++;
                        if (previewStr.length < 32) previewStr += String.fromCharCode(dec);
                    } else if (previewStr.length < 32) {
                        previewStr += '.';
                    }
                }
                
                const score = printable / dataToTest.length;
                results.push({ key, score, preview: previewStr });
            }
            
            results.sort((a, b) => b.score - a.score);
            return results.slice(0, topN);
        },

        /**
         * AES Decryption using crypto API.
         * Works in Browser (WebCrypto) and Node.js.
         */
        async aesDecrypt(uint8Array, key, iv, mode, keySize) {
            try {
                if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
                    // Browser WebCrypto API
                    const algoMap = {
                        'CBC': { name: 'AES-CBC', iv: iv },
                        'CTR': { name: 'AES-CTR', counter: iv, length: 128 },
                        'GCM': { name: 'AES-GCM', iv: iv }
                    };
                    
                    if (!algoMap[mode]) throw new Error(`Unsupported mode for WebCrypto: ${mode}`);
                    
                    const cryptoKey = await crypto.subtle.importKey(
                        'raw',
                        key,
                        { name: algoMap[mode].name },
                        false,
                        ['decrypt']
                    );
                    
                    const decrypted = await crypto.subtle.decrypt(
                        algoMap[mode],
                        cryptoKey,
                        uint8Array
                    );
                    
                    return { success: true, data: new Uint8Array(decrypted), error: null };
                } else if (typeof require !== 'undefined') {
                    // Node.js Crypto API (dynamic require to keep UMD intact)
                    const cryptoNode = require('crypto');
                    const modeMap = {
                        'CBC': `aes-${keySize}-cbc`,
                        'ECB': `aes-${keySize}-ecb`,
                        'CTR': `aes-${keySize}-ctr`,
                        'GCM': `aes-${keySize}-gcm`
                    };
                    
                    if (!modeMap[mode]) throw new Error(`Unsupported mode: ${mode}`);
                    
                    const decipher = cryptoNode.createDecipheriv(modeMap[mode], key, iv);
                    let decrypted = decipher.update(uint8Array);
                    decrypted = Buffer.concat([decrypted, decipher.final()]);
                    
                    return { success: true, data: new Uint8Array(decrypted), error: null };
                } else {
                    throw new Error("No cryptographic API available in this environment");
                }
            } catch (err) {
                return { success: false, data: null, error: err.message };
            }
        },

        rc4Decrypt(uint8Array, key) {
            let keyBytes = key;
            if (typeof key === 'string') {
                keyBytes = new TextEncoder().encode(key);
            }
            if (!(keyBytes instanceof Uint8Array) || keyBytes.length === 0) {
                throw new Error("Invalid RC4 key");
            }
            
            const S = new Uint8Array(256);
            for (let i = 0; i < 256; i++) S[i] = i;
            
            let j = 0;
            for (let i = 0; i < 256; i++) {
                j = (j + S[i] + keyBytes[i % keyBytes.length]) % 256;
                const temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            
            let i = 0;
            j = 0;
            const result = new Uint8Array(uint8Array.length);
            for (let k = 0; k < uint8Array.length; k++) {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                const temp = S[i];
                S[i] = S[j];
                S[j] = temp;
                const K = S[(S[i] + S[j]) % 256];
                result[k] = uint8Array[k] ^ K;
            }
            
            return result;
        },

        rot13(text) {
            return this.rotN(text, 13);
        },

        rotN(text, n) {
            n = ((n % 26) + 26) % 26;
            return text.replace(/[a-zA-Z]/g, function(c) {
                const base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode(((c.charCodeAt(0) - base + n) % 26) + base);
            });
        },

        caesarBruteForce(text) {
            const results = [];
            for (let i = 1; i < 26; i++) {
                const dec = this.rotN(text, i);
                // simple score based on spaces and vowels
                const score = (dec.match(/[ aeiou]/gi) || []).length;
                results.push({ shift: i, text: dec, score });
            }
            return results.sort((a, b) => b.score - a.score);
        },

        customTransform(uint8Array, operations) {
            let data = new Uint8Array(uint8Array);
            
            for (const op of operations) {
                const result = new Uint8Array(data.length);
                for (let i = 0; i < data.length; i++) {
                    switch (op.type) {
                        case 'xor': result[i] = data[i] ^ op.value; break;
                        case 'add': result[i] = (data[i] + op.value) & 0xFF; break;
                        case 'sub': result[i] = (data[i] - op.value) & 0xFF; break;
                        case 'rol': result[i] = ((data[i] << op.value) | (data[i] >>> (8 - op.value))) & 0xFF; break;
                        case 'ror': result[i] = ((data[i] >>> op.value) | (data[i] << (8 - op.value))) & 0xFF; break;
                        case 'reverse': result[i] = data[data.length - 1 - i]; break;
                        case 'swap_nibbles': result[i] = ((data[i] & 0x0F) << 4) | ((data[i] & 0xF0) >>> 4); break;
                        case 'swap_endian':
                            if (op.size === 2 && i % 2 === 0 && i + 1 < data.length) {
                                result[i] = data[i+1]; result[i+1] = data[i]; i++;
                            } else if (op.size === 4 && i % 4 === 0 && i + 3 < data.length) {
                                result[i] = data[i+3]; result[i+1] = data[i+2]; result[i+2] = data[i+1]; result[i+3] = data[i]; i += 3;
                            } else {
                                result[i] = data[i];
                            }
                            break;
                        default: result[i] = data[i];
                    }
                }
                data = result;
            }
            return data;
        },

        parseKey(keyString, format) {
            if (format === 'hex') {
                const hex = keyString.replace(/\s+/g, '');
                const bytes = new Uint8Array(hex.length / 2);
                for (let i = 0; i < bytes.length; i++) {
                    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
                }
                return bytes;
            } else if (format === 'base64') {
                const bin = (typeof window !== 'undefined' && window.atob) ? window.atob(keyString) : require('buffer').Buffer.from(keyString, 'base64').toString('binary');
                const bytes = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                return bytes;
            } else {
                return new TextEncoder().encode(keyString);
            }
        },

        detectEncryption(uint8Array) {
            let hints = [];
            let confidence = 0;
            
            // Check entropy
            let entropy = 0;
            const freq = new Uint32Array(256);
            for (let i = 0; i < uint8Array.length; i++) freq[uint8Array[i]]++;
            for (let i = 0; i < 256; i++) {
                if (freq[i] > 0) {
                    const p = freq[i] / uint8Array.length;
                    entropy -= p * Math.log2(p);
                }
            }
            
            if (entropy > 7.5) {
                confidence += 50;
                hints.push('High entropy (> 7.5)');
            } else if (entropy > 7.0) {
                confidence += 20;
                hints.push('Moderate entropy (> 7.0), possibly compressed');
            }
            
            // Known headers
            const str = Array.from(uint8Array.subarray(0, 16)).map(b => String.fromCharCode(b)).join('');
            if (str.startsWith('Salted__')) {
                confidence += 50;
                hints.push('OpenSSL Salted__ magic bytes found');
            }
            
            return {
                isLikelyEncrypted: confidence > 50,
                confidence: Math.min(confidence, 100),
                hints
            };
        }
    };

    return DecryptionEngine;
});
