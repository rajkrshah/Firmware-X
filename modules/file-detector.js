(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.FileDetector = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @typedef {Object} Signature
     * @property {string} type
     * @property {string} name
     * @property {string} description
     * @property {number} offset
     * @property {function(Uint8Array): boolean} match
     */

    const signatures = [
        { type: 'elf', name: 'ELF', description: 'Executable and Linkable Format', match: (buf) => buf.length >= 4 && buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46 },
        { type: 'pe', name: 'PE/MZ', description: 'Windows PE Executable', match: (buf) => buf.length >= 2 && buf[0] === 0x4D && buf[1] === 0x5A },
        { type: 'zip', name: 'ZIP', description: 'ZIP Archive', match: (buf) => buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4B && ((buf[2] === 0x03 && buf[3] === 0x04) || (buf[2] === 0x05 && buf[3] === 0x06) || (buf[2] === 0x07 && buf[3] === 0x08)) },
        { type: 'gzip', name: 'GZIP', description: 'GZIP Archive', match: (buf) => buf.length >= 3 && buf[0] === 0x1F && buf[1] === 0x8B && buf[2] === 0x08 },
        { type: '7z', name: '7z', description: '7-Zip Archive', match: (buf) => buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7A && buf[2] === 0xBC && buf[3] === 0xAF && buf[4] === 0x27 && buf[5] === 0x1C },
        { type: 'rar', name: 'RAR', description: 'RAR Archive', match: (buf) => buf.length >= 6 && buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21 && buf[4] === 0x1A && buf[5] === 0x07 },
        { type: 'tar', name: 'TAR', description: 'TAR Archive', match: (buf) => {
            if (buf.length < 262) return false;
            const magic = String.fromCharCode.apply(null, buf.slice(257, 262));
            return magic === 'ustar';
        }},
        { type: 'bzip2', name: 'BZIP2', description: 'BZIP2 Archive', match: (buf) => buf.length >= 3 && buf[0] === 0x42 && buf[1] === 0x5A && buf[2] === 0x68 },
        { type: 'xz', name: 'XZ', description: 'XZ Archive', match: (buf) => buf.length >= 6 && buf[0] === 0xFD && buf[1] === 0x37 && buf[2] === 0x7A && buf[3] === 0x58 && buf[4] === 0x5A && buf[5] === 0x00 },
        { type: 'lzma', name: 'LZMA', description: 'LZMA Archive', match: (buf) => buf.length >= 3 && buf[0] === 0x5D && buf[1] === 0x00 && buf[2] === 0x00 },
        { type: 'lz4', name: 'LZ4', description: 'LZ4 Archive', match: (buf) => buf.length >= 4 && buf[0] === 0x04 && buf[1] === 0x22 && buf[2] === 0x4D && buf[3] === 0x18 },
        { type: 'zstd', name: 'Zstandard', description: 'Zstandard Archive', match: (buf) => buf.length >= 4 && buf[0] === 0x28 && buf[1] === 0xB5 && buf[2] === 0x2F && buf[3] === 0xFD },
        { type: 'squashfs', name: 'SquashFS', description: 'SquashFS File System', match: (buf) => buf.length >= 4 && ((buf[0] === 0x68 && buf[1] === 0x73 && buf[2] === 0x71 && buf[3] === 0x73) || (buf[0] === 0x73 && buf[1] === 0x71 && buf[2] === 0x73 && buf[3] === 0x68)) },
        { type: 'cramfs', name: 'CramFS', description: 'CramFS File System', match: (buf) => buf.length >= 4 && ((buf[0] === 0x45 && buf[1] === 0x3D && buf[2] === 0xCD && buf[3] === 0x28) || (buf[0] === 0x28 && buf[1] === 0xCD && buf[2] === 0x3D && buf[3] === 0x45)) },
        { type: 'jffs2', name: 'JFFS2', description: 'JFFS2 File System', match: (buf) => buf.length >= 2 && ((buf[0] === 0x85 && buf[1] === 0x19) || (buf[0] === 0x19 && buf[1] === 0x85)) },
        { type: 'ubifs', name: 'UBIFS', description: 'UBIFS File System', match: (buf) => buf.length >= 4 && buf[0] === 0x31 && buf[1] === 0x18 && buf[2] === 0x10 && buf[3] === 0x06 },
        { type: 'uimage', name: 'uImage', description: 'U-Boot Image', match: (buf) => buf.length >= 4 && buf[0] === 0x27 && buf[1] === 0x05 && buf[2] === 0x19 && buf[3] === 0x56 },
        { type: 'android_boot', name: 'Android Boot', description: 'Android Boot Image', match: (buf) => buf.length >= 8 && buf[0] === 0x41 && buf[1] === 0x4E && buf[2] === 0x44 && buf[3] === 0x52 && buf[4] === 0x4F && buf[5] === 0x49 && buf[6] === 0x44 && buf[7] === 0x21 },
        { type: 'android_sparse', name: 'Android Sparse', description: 'Android Sparse Image', match: (buf) => buf.length >= 4 && buf[0] === 0x3A && buf[1] === 0xFF && buf[2] === 0x26 && buf[3] === 0xED },
        { type: 'fit', name: 'FIT', description: 'Flattened Image Tree', match: (buf) => buf.length >= 4 && buf[0] === 0xD0 && buf[1] === 0x0D && buf[2] === 0xFE && buf[3] === 0xED },
        { type: 'ihex', name: 'Intel HEX', description: 'Intel HEX Firmware', match: (buf) => {
            if (buf.length < 11) return false;
            if (buf[0] !== 0x3A) return false; // ':'
            for (let i = 1; i < 11; i++) {
                const c = buf[i];
                if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102))) return false;
            }
            return true;
        }},
        { type: 'srec', name: 'Motorola SREC', description: 'Motorola S-Record Firmware', match: (buf) => {
            if (buf.length < 10) return false;
            if (buf[0] !== 0x53) return false; // 'S'
            const type = buf[1];
            if (type < 48 || type > 57) return false; // '0'-'9'
            for (let i = 2; i < 10; i++) {
                const c = buf[i];
                if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102))) return false;
            }
            return true;
        }},
        { type: 'uf2', name: 'UF2', description: 'UF2 Firmware', match: (buf) => {
            if (buf.length < 512) return false;
            return buf[0] === 0x55 && buf[1] === 0x46 && buf[2] === 0x32 && buf[3] === 0x0A &&
                   buf[4] === 0x57 && buf[5] === 0x51 && buf[6] === 0x5D && buf[7] === 0x9E;
        }},
        { type: 'dfu', name: 'DFU', description: 'Device Firmware Upgrade', match: (buf) => {
            if (buf.length < 16) return false;
            const end = buf.length;
            return buf[end-5] === 0x55 && buf[end-4] === 0x46 && buf[end-3] === 0x44; // 'UFD'
        }},
        { type: 'pdf', name: 'PDF', description: 'PDF Document', match: (buf) => buf.length >= 4 && buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46 },
        { type: 'png', name: 'PNG', description: 'PNG Image', match: (buf) => buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 && buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A },
        { type: 'jpeg', name: 'JPEG', description: 'JPEG Image', match: (buf) => buf.length >= 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF },
        { type: 'gif', name: 'GIF', description: 'GIF Image', match: (buf) => buf.length >= 4 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38 },
        { type: 'bmp', name: 'BMP', description: 'BMP Image', match: (buf) => buf.length >= 2 && buf[0] === 0x42 && buf[1] === 0x4D },
        { type: 'wav', name: 'WAV', description: 'WAV Audio', match: (buf) => buf.length >= 12 && buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 && buf[8] === 0x57 && buf[9] === 0x41 && buf[10] === 0x56 && buf[11] === 0x45 },
        { type: 'macho', name: 'Mach-O', description: 'Mach-O Executable', match: (buf) => buf.length >= 4 && ((buf[0] === 0xFE && buf[1] === 0xED && buf[2] === 0xFA && buf[3] === 0xCE) || (buf[0] === 0xFE && buf[1] === 0xED && buf[2] === 0xFA && buf[3] === 0xCF) || (buf[0] === 0xCE && buf[1] === 0xFA && buf[2] === 0xED && buf[3] === 0xFE) || (buf[0] === 0xCF && buf[1] === 0xFA && buf[2] === 0xED && buf[3] === 0xFE)) },
        { type: 'javaclass', name: 'Java Class', description: 'Java Class File', match: (buf) => buf.length >= 4 && buf[0] === 0xCA && buf[1] === 0xFE && buf[2] === 0xBA && buf[3] === 0xBE },
        { type: 'dex', name: 'DEX', description: 'Android DEX', match: (buf) => buf.length >= 4 && buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0A },
        { type: 'sqlite', name: 'SQLite', description: 'SQLite Database', match: (buf) => {
            if (buf.length < 16) return false;
            const magic = [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00];
            for(let i=0; i<16; i++) if (buf[i] !== magic[i]) return false;
            return true;
        }},
        { type: 'cpio', name: 'CPIO', description: 'CPIO Archive', match: (buf) => buf.length >= 6 && ((buf[0] === 0x30 && buf[1] === 0x37 && buf[2] === 0x30 && buf[3] === 0x37 && buf[4] === 0x30) || (buf[0] === 0xC7 && buf[1] === 0x71)) },
        { type: 'ar', name: 'AR', description: 'AR Archive', match: (buf) => {
            if(buf.length < 7) return false;
            const magic = [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E];
            for(let i=0; i<7; i++) if (buf[i] !== magic[i]) return false;
            return true;
        }},
        { type: 'iso9660', name: 'ISO 9660', description: 'ISO 9660 File System', match: (buf) => {
            if (buf.length < 0x8006) return false;
            const magic = [0x43, 0x44, 0x30, 0x30, 0x31]; // CD001
            for(let i=0; i<5; i++) if (buf[0x8001 + i] !== magic[i]) return false;
            return true;
        }},
        { type: 'extfs', name: 'ext2/3/4', description: 'ext File System', match: (buf) => {
            if (buf.length < 0x43A) return false;
            return buf[0x438] === 0x53 && buf[0x439] === 0xEF; // 0xEF53 little endian
        }},
        { type: 'luks', name: 'LUKS', description: 'LUKS Encrypted Partition', match: (buf) => buf.length >= 6 && buf[0] === 0x4C && buf[1] === 0x55 && buf[2] === 0x4B && buf[3] === 0x53 && buf[4] === 0xBA && buf[5] === 0xBE },
        { type: 'openssl', name: 'OpenSSL', description: 'OpenSSL Encrypted Data', match: (buf) => {
            if (buf.length < 8) return false;
            const magic = [0x53, 0x61, 0x6C, 0x74, 0x65, 0x64, 0x5F, 0x5F]; // Salted__
            for(let i=0; i<8; i++) if (buf[i] !== magic[i]) return false;
            return true;
        }}
    ];

    class FileDetector {
        /**
         * Detect file type at offset 0
         * @param {Uint8Array} uint8Array 
         * @returns {Object|null}
         */
        detect(uint8Array) {
            if (!uint8Array || !(uint8Array instanceof Uint8Array)) {
                throw new Error("Invalid input: must be Uint8Array");
            }
            
            for (let sig of signatures) {
                if (sig.match(uint8Array)) {
                    return {
                        type: sig.type,
                        name: sig.name,
                        description: sig.description,
                        confidence: 1.0
                    };
                }
            }
            return null;
        }

        /**
         * Scan entire buffer for all embedded signatures
         * @param {Uint8Array} uint8Array 
         * @returns {Array<Object>}
         */
        scanAll(uint8Array) {
            if (!uint8Array || !(uint8Array instanceof Uint8Array)) {
                throw new Error("Invalid input: must be Uint8Array");
            }

            const results = [];
            const len = uint8Array.length;
            const MAX_RESULTS = 200; // Cap to prevent UI/perf issues

            // Build a first-byte lookup table for fast filtering
            // Group signatures by their first magic byte so we only test
            // relevant signatures at each offset instead of all 40+
            const firstByteLookup = {};
            const specialSigs = []; // Signatures that need special offset checks (tar, iso, ext, dfu)
            for (const sig of signatures) {
                // Identify "special" signatures that check non-zero offsets
                if (sig.type === 'tar' || sig.type === 'iso9660' || sig.type === 'extfs' || sig.type === 'dfu') {
                    specialSigs.push(sig);
                    continue;
                }
                // For normal signatures, determine their first byte by testing a synthetic buffer
                // We test all 256 possible first bytes to find which ones the match function accepts
                for (let b = 0; b < 256; b++) {
                    const testBuf = new Uint8Array(1024);
                    testBuf[0] = b;
                    // We can't fully test with just first byte, so we'll use a simpler approach:
                    // just store the signature for all first bytes and let match() filter
                    if (!firstByteLookup[b]) firstByteLookup[b] = [];
                }
            }
            // Simpler approach: for each offset, check first byte and only test sigs starting with that byte
            // Build lookup from known first bytes of each signature
            const knownFirstBytes = {
                0x7F: ['elf'], 0x4D: ['pe'], 0x50: ['zip'], 0x1F: ['gzip'],
                0x37: ['7z'], 0x52: ['rar', 'wav'], 0x42: ['bzip2', 'bmp'],
                0xFD: ['xz'], 0x5D: ['lzma'], 0x04: ['lz4'], 0x28: ['zstd', 'cramfs'],
                0x68: ['squashfs'], 0x73: ['squashfs'], 0x45: ['cramfs'],
                0x85: ['jffs2'], 0x19: ['jffs2'], 0x31: ['ubifs'],
                0x27: ['uimage'], 0x41: ['android_boot'], 0x3A: ['android_sparse', 'ihex'],
                0xD0: ['fit'], 0x53: ['srec', 'sqlite'], 0x55: ['uf2'],
                0x25: ['pdf'], 0x89: ['png'], 0xFF: ['jpeg'],
                0x47: ['gif'], 0xFE: ['macho'], 0xCE: ['macho'], 0xCF: ['macho'],
                0xCA: ['javaclass'], 0x64: ['dex'], 0x30: ['cpio'], 0xC7: ['cpio'],
                0x21: ['ar'], 0x4C: ['luks']
            };

            // Build type -> signature map
            const sigByType = {};
            for (const sig of signatures) {
                sigByType[sig.type] = sig;
            }

            for (let offset = 0; offset < len && results.length < MAX_RESULTS; offset++) {
                const byte0 = uint8Array[offset];
                const candidateTypes = knownFirstBytes[byte0];
                if (candidateTypes) {
                    const slice = uint8Array.subarray(offset, Math.min(len, offset + 1024));
                    for (const type of candidateTypes) {
                        const sig = sigByType[type];
                        if (sig && sig.match(slice)) {
                            // Avoid consecutive duplicates of same type
                            if (results.length > 0 && results[results.length-1].offset === offset && results[results.length-1].type === type) {
                                continue;
                            }
                            let magicBytes = Array.from(slice.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                            results.push({
                                type: sig.type,
                                name: sig.name,
                                offset: offset,
                                description: sig.description,
                                magicBytes: magicBytes
                            });
                            break; // Only one match per offset
                        }
                    }
                }
            }

            // Also check special sigs (tar at offset+257, iso at 0x8001, ext at 0x438)
            for (const sig of specialSigs) {
                if (results.length >= MAX_RESULTS) break;
                if (sig.type === 'tar') {
                    // Scan for ustar magic at every 512-byte boundary
                    for (let offset = 0; offset < len - 262 && results.length < MAX_RESULTS; offset += 512) {
                        const slice = uint8Array.subarray(offset, Math.min(len, offset + 1024));
                        if (sig.match(slice)) {
                            results.push({ type: sig.type, name: sig.name, offset, description: sig.description, magicBytes: 'ustar' });
                        }
                    }
                } else {
                    // iso9660, extfs, dfu — just check once from the start of buffer
                    const slice = uint8Array.subarray(0, Math.min(len, 0x8010));
                    if (sig.match(slice)) {
                        results.push({ type: sig.type, name: sig.name, offset: 0, description: sig.description, magicBytes: '' });
                    }
                }
            }

            // Sort by offset
            results.sort(function(a, b) { return a.offset - b.offset; });
            return results;
        }
    }

    return FileDetector;
});
