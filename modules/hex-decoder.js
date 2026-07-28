(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.HexDecoder = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    class HexDecoder {
        decodeIntelHex(text) {
            const lines = text.split(/\r?\n/);
            const regions = [];
            let entryPoint = null;
            let extendedSegment = 0;
            let extendedLinear = 0;

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line || line[0] !== ':') continue;

                const byteCount = parseInt(line.substr(1, 2), 16);
                const address = parseInt(line.substr(3, 4), 16);
                const recordType = parseInt(line.substr(7, 2), 16);
                const dataHex = line.substr(9, byteCount * 2);
                
                let checksum = 0;
                for (let j = 0; j < (byteCount + 4); j++) {
                    checksum += parseInt(line.substr(1 + j * 2, 2), 16);
                }
                const calculatedChecksum = (-checksum) & 0xFF;
                const fileChecksum = parseInt(line.substr(9 + byteCount * 2, 2), 16);
                
                if (calculatedChecksum !== fileChecksum) {
                    throw new Error(`Checksum mismatch at line ${i + 1}`);
                }

                if (recordType === 0x00) { // Data
                    const absoluteAddress = address + extendedSegment + extendedLinear;
                    const data = new Uint8Array(byteCount);
                    for (let j = 0; j < byteCount; j++) {
                        data[j] = parseInt(dataHex.substr(j * 2, 2), 16);
                    }
                    regions.push({ address: absoluteAddress, data });
                } else if (recordType === 0x01) { // EOF
                    break;
                } else if (recordType === 0x02) { // Extended Segment
                    extendedSegment = parseInt(dataHex, 16) * 16;
                } else if (recordType === 0x03) { // Start Segment
                    entryPoint = parseInt(dataHex, 16);
                } else if (recordType === 0x04) { // Extended Linear
                    extendedLinear = parseInt(dataHex, 16) << 16;
                } else if (recordType === 0x05) { // Start Linear
                    entryPoint = parseInt(dataHex, 16);
                }
            }

            return this._mergeRegions(regions, entryPoint);
        }

        decodeSRecord(text) {
            const lines = text.split(/\r?\n/);
            const regions = [];
            let entryPoint = null;

            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line || line[0] !== 'S') continue;

                const type = parseInt(line[1], 10);
                const byteCount = parseInt(line.substr(2, 2), 16);
                
                let checksum = byteCount;
                for (let j = 0; j < byteCount - 1; j++) {
                    checksum += parseInt(line.substr(4 + j * 2, 2), 16);
                }
                const calculatedChecksum = (~checksum) & 0xFF;
                const fileChecksum = parseInt(line.substr(4 + (byteCount - 1) * 2, 2), 16);
                
                if (calculatedChecksum !== fileChecksum) {
                    throw new Error(`Checksum mismatch at line ${i + 1}`);
                }

                let addressBytes = 2;
                if (type === 2 || type === 8) addressBytes = 3;
                if (type === 3 || type === 7) addressBytes = 4;

                const addressStr = line.substr(4, addressBytes * 2);
                const address = parseInt(addressStr, 16);

                if (type >= 1 && type <= 3) {
                    const dataLen = byteCount - addressBytes - 1;
                    const data = new Uint8Array(dataLen);
                    const dataHex = line.substr(4 + addressBytes * 2, dataLen * 2);
                    for (let j = 0; j < dataLen; j++) {
                        data[j] = parseInt(dataHex.substr(j * 2, 2), 16);
                    }
                    regions.push({ address, data });
                } else if (type >= 7 && type <= 9) {
                    entryPoint = address;
                }
            }

            return this._mergeRegions(regions, entryPoint);
        }

        _mergeRegions(regions, entryPoint) {
            if (regions.length === 0) return { data: new Uint8Array(0), startAddress: 0, entryPoint, regions };
            
            regions.sort((a, b) => a.address - b.address);
            
            const startAddress = regions[0].address;
            const endAddress = regions[regions.length - 1].address + regions[regions.length - 1].data.length;
            const totalSize = endAddress - startAddress;
            
            const merged = new Uint8Array(totalSize);
            for (let region of regions) {
                merged.set(region.data, region.address - startAddress);
            }
            
            return { data: merged, startAddress, entryPoint, regions };
        }

        decodeUF2(uint8Array) {
            if (uint8Array.length < 512 || uint8Array.length % 512 !== 0) {
                throw new Error("Invalid UF2 file size");
            }

            const dv = new DataView(uint8Array.buffer, uint8Array.byteOffset, uint8Array.byteLength);
            let startAddress = null;
            let familyId = null;
            let totalBlocks = 0;
            const blocks = [];

            for (let offset = 0; offset < uint8Array.length; offset += 512) {
                const magic0 = dv.getUint32(offset, true);
                const magic1 = dv.getUint32(offset + 4, true);
                const flags = dv.getUint32(offset + 8, true);
                const targetAddr = dv.getUint32(offset + 12, true);
                const payloadSize = dv.getUint32(offset + 16, true);
                const blockNo = dv.getUint32(offset + 20, true);
                const numBlocks = dv.getUint32(offset + 24, true);
                const family = dv.getUint32(offset + 28, true);
                const magicEnd = dv.getUint32(offset + 508, true);

                if (magic0 !== 0x0A324655 || magic1 !== 0x9E5D5157 || magicEnd !== 0x0AB16F30) {
                    continue; // Skip invalid block
                }

                if (startAddress === null) startAddress = targetAddr;
                if ((flags & 0x00002000) !== 0) familyId = family;
                totalBlocks = numBlocks;

                blocks.push({
                    address: targetAddr,
                    data: uint8Array.slice(offset + 32, offset + 32 + payloadSize)
                });
            }

            return Object.assign(this._mergeRegions(blocks, null), { familyId, blockCount: totalBlocks });
        }

        decodeDFU(uint8Array) {
            if (uint8Array.length < 16) throw new Error("File too small for DFU");
            const suffix = uint8Array.slice(-16);
            const dv = new DataView(suffix.buffer, suffix.byteOffset, suffix.byteLength);
            
            const magic = String.fromCharCode(suffix[10], suffix[11], suffix[12]);
            if (magic !== 'UFD') return { hasSuffix: false };
            
            return {
                hasSuffix: true,
                version: dv.getUint16(0, true),
                vendorId: dv.getUint16(2, true),
                productId: dv.getUint16(4, true),
                dfuVersion: dv.getUint16(6, true),
                data: uint8Array.slice(0, -16)
            };
        }
        
        isTextFormat(uint8Array) {
            return this.detectTextFormat(uint8Array) !== null;
        }

        detectTextFormat(uint8Array) {
            if (uint8Array.length < 10) return null;
            if (uint8Array[0] === 0x3A) return 'ihex';
            if (uint8Array[0] === 0x53) return 'srec';
            return null;
        }
    }

    return HexDecoder;
});
