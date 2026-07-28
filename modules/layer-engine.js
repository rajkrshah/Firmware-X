(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.LayerEngine = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    class LayerEngine {
        /**
         * @param {Object} fileDetector 
         * @param {Object} archiveExtractor 
         * @param {Object} hexDecoder 
         * @param {Object} options 
         */
        constructor(fileDetector, archiveExtractor, hexDecoder, options = {}) {
            this.fileDetector = fileDetector;
            this.archiveExtractor = archiveExtractor;
            this.hexDecoder = hexDecoder;
            this.maxDepth = options.maxDepth || 10;
            this.maxLayers = options.maxLayers || 100;
            this.layers = new Map();
            this.layerCount = 0;
            this.maxDepthReached = 0;
            this.rootLayerId = null;
            this.stats = { totalLayers: 0, maxDepthReached: 0, types: {} };
            this.onProgress = options.onProgress || function() {};
        }

        /**
         * Analyze a buffer and build a tree of layers
         * @param {Uint8Array} uint8Array 
         * @param {string} filename 
         */
        async analyze(uint8Array, filename = 'root') {
            this.layers.clear();
            this.layerCount = 0;
            this.stats = { totalLayers: 0, maxDepthReached: 0, types: {} };
            
            const rootLayer = await this._processLayer(uint8Array, filename, 0);
            this.rootLayerId = rootLayer.id;
            return rootLayer;
        }

        async _processLayer(data, name, depth) {
            if (depth > this.stats.maxDepthReached) {
                this.stats.maxDepthReached = depth;
            }

            const id = `layer_${this.layerCount++}`;
            this.stats.totalLayers++;
            this.onProgress(this.layerCount, depth, `Processing ${name}`);

            const layer = {
                id,
                name,
                type: 'unknown',
                size: data.length,
                offset: 0,
                data: data,
                children: [],
                metadata: {}
            };

            this.layers.set(id, layer);

            if (depth >= this.maxDepth || this.layerCount >= this.maxLayers) {
                return layer;
            }

            // Detect type
            const detection = this.fileDetector.detect(data);
            if (detection) {
                layer.type = detection.type;
                layer.metadata.description = detection.description;
                this.stats.types[detection.type] = (this.stats.types[detection.type] || 0) + 1;

                // If text hex format, decode first
                if (detection.type === 'ihex' || detection.type === 'srec') {
                    const text = new TextDecoder().decode(data);
                    const decoded = detection.type === 'ihex' ? this.hexDecoder.decodeIntelHex(text) : this.hexDecoder.decodeSRecord(text);
                    if (decoded && decoded.data) {
                        const child = await this._processLayer(decoded.data, `${name}.bin`, depth + 1);
                        layer.children.push(child);
                        return layer; // stop after decoding hex
                    }
                }

                if (detection.type === 'uf2') {
                    const decoded = this.hexDecoder.decodeUF2(data);
                    if (decoded && decoded.data) {
                        const child = await this._processLayer(decoded.data, `${name}.bin`, depth + 1);
                        layer.children.push(child);
                        return layer;
                    }
                }

                // If extractable
                if (this.archiveExtractor && this.archiveExtractor.canExtract(detection.type)) {
                    try {
                        const extracted = await this.archiveExtractor.extract(data, detection.type);
                        if (Array.isArray(extracted)) {
                            for (let ext of extracted) {
                                if (ext.isDirectory) continue;
                                const child = await this._processLayer(ext.data, ext.name, depth + 1);
                                layer.children.push(child);
                            }
                        } else if (extracted instanceof Uint8Array) {
                            const child = await this._processLayer(extracted, `${name}.extracted`, depth + 1);
                            layer.children.push(child);
                        }
                    } catch (e) {
                        layer.metadata.extractionError = e.message;
                    }
                }
            }

            // ── Deep Scan: find ALL embedded signatures at arbitrary offsets ──
            // This is critical for raw firmware binaries that contain embedded
            // filesystems, compressed streams, and executables at non-zero offsets.
            if (this.fileDetector && this.fileDetector.scanAll && data.length > 64) {
                try {
                    const allSigs = this.fileDetector.scanAll(data);
                    // Deduplicate: skip signatures at offset 0 (already handled above)
                    // and group by offset to avoid redundant layers
                    const seenOffsets = new Set();
                    if (layer.type !== 'unknown') {
                        seenOffsets.add(0); // root detection already covered offset 0
                    }

                    for (const sig of allSigs) {
                        if (seenOffsets.has(sig.offset)) continue;
                        if (this.layerCount >= this.maxLayers) break;

                        // Skip tiny matches (likely false positives)
                        const remainingBytes = data.length - sig.offset;
                        if (remainingBytes < 32) continue;

                        seenOffsets.add(sig.offset);

                        // Create a child layer for this embedded signature
                        const embeddedData = data.subarray(sig.offset);
                        const childLayer = {
                            id: `layer_${this.layerCount++}`,
                            name: `${sig.name} @ 0x${sig.offset.toString(16).toUpperCase()}`,
                            type: sig.type,
                            size: remainingBytes,
                            offset: sig.offset,
                            data: embeddedData,
                            children: [],
                            metadata: {
                                description: sig.description,
                                magicBytes: sig.magicBytes,
                                embeddedOffset: sig.offset
                            }
                        };

                        this.stats.totalLayers++;
                        this.stats.types[sig.type] = (this.stats.types[sig.type] || 0) + 1;
                        this.layers.set(childLayer.id, childLayer);

                        // Try to extract extractable embedded archives (ZIP, GZIP, TAR, etc.)
                        if (this.archiveExtractor && this.archiveExtractor.canExtract(sig.type)) {
                            try {
                                const extracted = await this.archiveExtractor.extract(embeddedData, sig.type);
                                if (Array.isArray(extracted)) {
                                    for (let ext of extracted) {
                                        if (ext.isDirectory) continue;
                                        if (this.layerCount >= this.maxLayers) break;
                                        const grandChild = await this._processLayer(ext.data, ext.name, depth + 2);
                                        childLayer.children.push(grandChild);
                                    }
                                } else if (extracted instanceof Uint8Array) {
                                    const grandChild = await this._processLayer(extracted, `${sig.name}.extracted`, depth + 2);
                                    childLayer.children.push(grandChild);
                                }
                            } catch (e) {
                                childLayer.metadata.extractionError = e.message;
                            }
                        }

                        layer.children.push(childLayer);
                    }
                } catch (scanErr) {
                    layer.metadata.deepScanError = scanErr.message;
                }
            }

            return layer;
        }

        getLayerTree() {
            if (!this.rootLayerId) return null;
            return this.getLayerById(this.rootLayerId);
        }

        getLayerById(id) {
            return this.layers.get(id) || null;
        }

        getStats() {
            return this.stats;
        }
    }

    return LayerEngine;
});
