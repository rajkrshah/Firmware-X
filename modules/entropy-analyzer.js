(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.EntropyAnalyzer = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @class EntropyAnalyzer
     * Analyzes Shannon entropy and byte distribution for binary data.
     */
    const EntropyAnalyzer = {
        /**
         * Analyzes a binary buffer to calculate Shannon entropy and identify block regions.
         * @param {Uint8Array} uint8Array - The binary data.
         * @param {number} [blockSize=256] - The size of each block for analysis.
         * @returns {Object} Analysis results containing blocks, overall entropy, byte frequency, and merged regions.
         */
        analyze(uint8Array, blockSize = 256) {
            if (!(uint8Array instanceof Uint8Array)) {
                throw new Error("Input must be a Uint8Array");
            }

            const length = uint8Array.length;
            const overallFreq = new Uint32Array(256);
            const blocks = [];
            
            for (let offset = 0; offset < length; offset += blockSize) {
                const currentBlockSize = Math.min(blockSize, length - offset);
                const blockFreq = new Uint32Array(256);
                
                for (let i = 0; i < currentBlockSize; i++) {
                    const byte = uint8Array[offset + i];
                    blockFreq[byte]++;
                    overallFreq[byte]++;
                }
                
                let entropy = 0;
                for (let i = 0; i < 256; i++) {
                    if (blockFreq[i] > 0) {
                        const p = blockFreq[i] / currentBlockSize;
                        entropy -= p * Math.log2(p);
                    }
                }
                
                blocks.push({
                    offset,
                    entropy,
                    classification: this._classifyEntropy(entropy)
                });
            }

            let overallEntropy = 0;
            for (let i = 0; i < 256; i++) {
                if (overallFreq[i] > 0) {
                    const p = overallFreq[i] / length;
                    overallEntropy -= p * Math.log2(p);
                }
            }

            return {
                blocks,
                overall: overallEntropy,
                byteFrequency: overallFreq,
                regions: this._detectRegions(blocks, blockSize, length)
            };
        },

        _classifyEntropy(entropy) {
            if (entropy < 0.5) return 'empty';
            if (entropy < 3.5) return 'structured';
            if (entropy < 5.0) return 'text';
            if (entropy < 6.5) return 'code';
            if (entropy < 7.5) return 'compressed';
            return 'encrypted';
        },

        _detectRegions(blocks, blockSize, totalLength) {
            if (blocks.length === 0) return [];
            
            const regions = [];
            let currentRegion = {
                start: blocks[0].offset,
                end: Math.min(blocks[0].offset + blockSize, totalLength),
                type: blocks[0].classification,
                entropySum: blocks[0].entropy,
                count: 1
            };
            
            for (let i = 1; i < blocks.length; i++) {
                const block = blocks[i];
                if (block.classification === currentRegion.type) {
                    currentRegion.end = Math.min(block.offset + blockSize, totalLength);
                    currentRegion.entropySum += block.entropy;
                    currentRegion.count++;
                } else {
                    currentRegion.avgEntropy = currentRegion.entropySum / currentRegion.count;
                    delete currentRegion.entropySum;
                    delete currentRegion.count;
                    regions.push(currentRegion);
                    
                    currentRegion = {
                        start: block.offset,
                        end: Math.min(block.offset + blockSize, totalLength),
                        type: block.classification,
                        entropySum: block.entropy,
                        count: 1
                    };
                }
            }
            
            currentRegion.avgEntropy = currentRegion.entropySum / currentRegion.count;
            delete currentRegion.entropySum;
            delete currentRegion.count;
            regions.push(currentRegion);
            
            return regions;
        },

        /**
         * Calculates byte distribution and chi-squared to detect randomness.
         * @param {Uint8Array} uint8Array - The binary data.
         * @returns {Object} Byte distribution histogram and chi-squared result.
         */
        getByteDistribution(uint8Array) {
            if (!(uint8Array instanceof Uint8Array)) throw new Error("Input must be a Uint8Array");
            
            const length = uint8Array.length;
            const histogram = new Uint32Array(256);
            for (let i = 0; i < length; i++) {
                histogram[uint8Array[i]]++;
            }
            
            const expected = length / 256;
            let chiSquared = 0;
            for (let i = 0; i < 256; i++) {
                chiSquared += Math.pow(histogram[i] - expected, 2) / expected;
            }
            
            // Critical value for alpha=0.01, df=255 is approx 310.45
            // If chiSquared < 310.45, it means distribution is uniform (likely random)
            const isRandom = chiSquared < 310.45;
            
            return { histogram, chiSquared, isRandom };
        },

        /**
         * Renders entropy data onto an HTML Canvas.
         * @param {HTMLCanvasElement} canvas - The canvas element.
         * @param {Array} blocks - Blocks from analyze().
         * @param {Object} options - Options {width, height, showGrid, showRegions, colorScheme}.
         */
        renderEntropyCanvas(canvas, blocks, options = {}) {
            if (!canvas || !canvas.getContext) throw new Error("Valid canvas element required");
            
            const ctx = canvas.getContext('2d');
            const width = options.width || canvas.width || 800;
            const height = options.height || canvas.height || 200;
            
            canvas.width = width;
            canvas.height = height;
            
            const showGrid = options.showGrid !== false;
            const showRegions = options.showRegions !== false;
            
            ctx.clearRect(0, 0, width, height);
            
            if (blocks.length === 0) return;
            
            const blockWidth = width / blocks.length;
            
            // Grid lines
            if (showGrid) {
                ctx.strokeStyle = '#ccc';
                ctx.beginPath();
                [2, 4, 6, 8].forEach(e => {
                    const y = height - (e / 8) * height;
                    ctx.moveTo(0, y);
                    ctx.lineTo(width, y);
                });
                ctx.stroke();
            }
            
            for (let i = 0; i < blocks.length; i++) {
                const block = blocks[i];
                const x = i * blockWidth;
                const h = (block.entropy / 8) * height;
                const y = height - h;
                
                ctx.fillStyle = this._getColorForEntropy(block.entropy);
                ctx.fillRect(x, y, blockWidth + 1, h); // +1 to overlap and avoid gaps
            }
        },

        _getColorForEntropy(entropy) {
            // blue (low) -> green (mid) -> yellow (high) -> red (very high)
            if (entropy < 2) return 'blue';
            if (entropy < 4) return 'green';
            if (entropy < 6) return 'yellow';
            return 'red';
        },

        /**
         * Renders an ASCII bar chart for CLI.
         * @param {Array} blocks - Blocks from analyze().
         * @param {number} width - Terminal width.
         * @returns {string} ASCII art representation of entropy.
         */
        renderAsciiEntropy(blocks, width = 80) {
            if (!blocks || blocks.length === 0) return '';
            
            const chars = ['░', '▒', '▓', '█'];
            let result = '';
            
            const chunks = Math.ceil(blocks.length / (width - 15));
            let chunkedBlocks = [];
            
            if (chunks > 1) {
                for (let i = 0; i < blocks.length; i += chunks) {
                    let sum = 0;
                    let count = 0;
                    for (let j = 0; j < chunks && i + j < blocks.length; j++) {
                        sum += blocks[i + j].entropy;
                        count++;
                    }
                    chunkedBlocks.push({ offset: blocks[i].offset, entropy: sum / count });
                }
            } else {
                chunkedBlocks = blocks;
            }
            
            chunkedBlocks.forEach(block => {
                const offsetStr = block.offset.toString(16).padStart(8, '0');
                const level = Math.floor((block.entropy / 8) * 4);
                const charIdx = Math.min(3, Math.max(0, level));
                const bar = chars[charIdx].repeat(Math.round(block.entropy * 2)); // scale to ~16 chars max
                
                let colorHint = '[LOW]';
                if (block.entropy >= 7.5) colorHint = '[CRYPT]';
                else if (block.entropy >= 5.0) colorHint = '[HIGH]';
                else if (block.entropy >= 3.5) colorHint = '[MED]';
                
                result += `0x${offsetStr} | ${bar.padEnd(16, ' ')} | ${block.entropy.toFixed(2)} ${colorHint}\n`;
            });
            
            return result;
        }
    };

    return EntropyAnalyzer;
});
