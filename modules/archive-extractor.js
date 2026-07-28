(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.ArchiveExtractor = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    class ArchiveExtractor {
        constructor(fflateLib = null, jszipLib = null) {
            this.fflate = fflateLib;
            this.jszip = jszipLib;
            this.supportedTypes = ['zip', 'gzip', 'tar'];
            if (this.fflate) {
                this.supportedTypes.push('zlib', 'deflate');
            }
        }

        canExtract(type) {
            return this.supportedTypes.includes(type);
        }

        async extract(uint8Array, type) {
            switch(type) {
                case 'zip': return this.extractZip(uint8Array);
                case 'gzip': return this.decompressGzip(uint8Array);
                case 'tar': return this.extractTar(uint8Array);
                case 'zlib': return this.decompressZlib(uint8Array);
                case 'deflate': return this.decompressDeflateRaw(uint8Array);
                case 'lzma': return this.decompressLzma(uint8Array);
                default: throw new Error(`Unsupported extraction type: ${type}`);
            }
        }

        async extractZip(uint8Array) {
            if (this.jszip) {
                const zip = await this.jszip.loadAsync(uint8Array);
                const results = [];
                for (const [name, file] of Object.entries(zip.files)) {
                    if (!file.dir) {
                        const data = await file.async("uint8array");
                        results.push({ name, data, isDirectory: false, size: data.length });
                    }
                }
                return results;
            } else if (this.fflate) {
                return new Promise((resolve, reject) => {
                    this.fflate.unzip(uint8Array, (err, unzipped) => {
                        if (err) return reject(err);
                        const results = [];
                        for (const [name, data] of Object.entries(unzipped)) {
                            if (data.length > 0) { // simple directory check
                                results.push({ name, data, isDirectory: false, size: data.length });
                            }
                        }
                        resolve(results);
                    });
                });
            }
            throw new Error("No ZIP library available (fflate or JSZip)");
        }

        decompressGzip(uint8Array) {
            if (this.fflate) {
                return this.fflate.gunzipSync(uint8Array);
            }
            throw new Error("No GZIP library available (fflate required)");
        }

        decompressZlib(uint8Array) {
            if (this.fflate) {
                return this.fflate.unzlibSync(uint8Array);
            }
            throw new Error("No ZLIB library available");
        }

        decompressDeflateRaw(uint8Array) {
            if (this.fflate) {
                return this.fflate.inflateSync(uint8Array);
            }
            throw new Error("No Deflate library available");
        }

        decompressLzma(uint8Array) {
            throw new Error("LZMA decompression not natively supported without external library");
        }

        extractTar(uint8Array) {
            const results = [];
            let offset = 0;
            const length = uint8Array.length;

            while (offset < length) {
                if (offset + 512 > length) break;
                
                const header = uint8Array.subarray(offset, offset + 512);
                let isEmpty = true;
                for (let i = 0; i < 512; i++) {
                    if (header[i] !== 0) {
                        isEmpty = false;
                        break;
                    }
                }
                if (isEmpty) {
                    offset += 512;
                    continue;
                }

                // Name is at 0-99
                let name = '';
                for (let i = 0; i < 100 && header[i] !== 0; i++) {
                    name += String.fromCharCode(header[i]);
                }

                // Size is at 124-135, octal ASCII
                let sizeStr = '';
                for (let i = 124; i < 135 && header[i] !== 0 && header[i] !== 32; i++) {
                    sizeStr += String.fromCharCode(header[i]);
                }
                const size = parseInt(sizeStr, 8);
                if (isNaN(size)) break;

                const typeFlag = String.fromCharCode(header[156]);
                
                offset += 512;

                if (typeFlag === '0' || typeFlag === '\0') { // Normal file
                    if (offset + size <= length) {
                        const data = uint8Array.slice(offset, offset + size);
                        results.push({ name, data, size, type: typeFlag, isDirectory: false });
                    }
                }
                
                // Advance offset to next 512 byte block
                offset += Math.ceil(size / 512) * 512;
            }

            return results;
        }
    }

    return ArchiveExtractor;
});
