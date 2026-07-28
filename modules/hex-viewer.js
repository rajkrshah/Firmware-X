(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.HexViewer = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @class HexViewer
     * Handles rendering of hex dumps for binary data in web and CLI environments.
     */
    class HexViewer {
        /**
         * @param {HTMLElement|null} containerElement - DOM element for web rendering, null for CLI mode.
         */
        constructor(containerElement = null) {
            this.container = containerElement;
            this.data = null;
            this.highlights = [];
            this.bytesPerRow = 16;
            this.selection = { start: -1, end: -1 };
        }

        /**
         * Sets the binary data to view.
         * @param {Uint8Array} uint8Array - Binary data.
         */
        setData(uint8Array) {
            if (!(uint8Array instanceof Uint8Array)) throw new Error("Data must be a Uint8Array");
            this.data = uint8Array;
        }

        /**
         * Renders the hex view.
         * @param {number} startOffset - Starting offset.
         * @param {number} numRows - Number of rows to render.
         * @returns {string} Rendered HTML or formatted string.
         */
        render(startOffset = 0, numRows = 20) {
            if (!this.data) return '';
            
            startOffset = Math.max(0, startOffset);
            startOffset -= startOffset % this.bytesPerRow; // align
            
            let output = '';
            const endRow = Math.min(startOffset + numRows * this.bytesPerRow, this.data.length);
            
            if (this.container) {
                output += '<div class="hex-viewer-header">OFFSET   | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII</div>\n';
            }
            
            for (let offset = startOffset; offset < endRow; offset += this.bytesPerRow) {
                const chunkLen = Math.min(this.bytesPerRow, this.data.length - offset);
                const chunk = this.data.subarray(offset, offset + chunkLen);
                const row = this.formatRow(offset, chunk);
                
                output += this.container ? `<div class="hex-row">${row.html}</div>\n` : `${row.offsetStr} | ${row.hexStr} | ${row.asciiStr}\n`;
            }
            
            if (this.container) {
                this.container.innerHTML = `<pre>${output}</pre>`;
            }
            return output;
        }
        
        scrollToOffset(offset) {
            if (!this.data) return;
            // Prevent scrolling out of bounds
            if (offset < 0) offset = 0;
            if (offset >= this.data.length) offset = this.data.length - 1;
            
            // Align offset to row boundary
            offset -= offset % this.bytesPerRow;
            
            // Render from new offset
            this.render(offset, 1024);
        }

        /**
         * Formats a single row of hex data.
         * @param {number} offset - Offset of the row.
         * @param {Uint8Array} bytes - Bytes in the row.
         * @returns {Object} Formatting parts.
         */
        formatRow(offset, bytes) {
            const offsetStr = offset.toString(16).padStart(8, '0').toUpperCase();
            let hexStr = '';
            let asciiStr = '';
            
            for (let i = 0; i < this.bytesPerRow; i++) {
                if (i === 8) hexStr += ' ';
                if (i < bytes.length) {
                    const byte = bytes[i];
                    hexStr += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';
                    asciiStr += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                } else {
                    hexStr += '   ';
                    asciiStr += ' ';
                }
            }
            
            const html = `<span class="offset">${offsetStr}</span> | <span class="hex">${hexStr.trimEnd()}</span> | <span class="ascii">${asciiStr.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>`;
            
            return { offsetStr, hexStr: hexStr.trimEnd(), asciiStr, html };
        }

        search(pattern, isHex, startFrom = 0) {
            if (!this.data) return [];
            const results = [];
            
            let searchBytes;
            if (isHex) {
                const hexStr = pattern.replace(/\s/g, '');
                searchBytes = new Uint8Array(Math.ceil(hexStr.length / 2));
                for(let i=0; i<searchBytes.length; i++) {
                    searchBytes[i] = parseInt(hexStr.substring(i*2, i*2+2), 16);
                }
            } else {
                searchBytes = new TextEncoder().encode(pattern);
            }
            
            if (searchBytes.length === 0) return results;
            
            for (let i = startFrom; i <= this.data.length - searchBytes.length; i++) {
                let match = true;
                for (let j = 0; j < searchBytes.length; j++) {
                    if (this.data[i + j] !== searchBytes[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    results.push({ offset: i, length: searchBytes.length });
                }
            }
            return results;
        }

        goToOffset(offset) {
            if (this.container) {
                // Implement scrolling logic if container exists
                const rowOffset = offset - (offset % this.bytesPerRow);
                this.render(rowOffset, 20); // Render starting at that row
            }
            return offset - (offset % this.bytesPerRow);
        }

        getSelection() {
            if (this.selection.start === -1) return null;
            return {
                start: this.selection.start,
                end: this.selection.end,
                bytes: this.data.subarray(this.selection.start, this.selection.end + 1)
            };
        }

        setHighlights(regions) {
            this.highlights = regions;
        }

        getTotalRows() {
            if (!this.data) return 0;
            return Math.ceil(this.data.length / this.bytesPerRow);
        }

        renderPage(pageNum, rowsPerPage = 20) {
            const startOffset = pageNum * rowsPerPage * this.bytesPerRow;
            return this.render(startOffset, rowsPerPage);
        }

        formatCLI(startOffset = 0, numRows = 20, highlightOffsets = []) {
            if (!this.data) return '';
            
            startOffset = Math.max(0, startOffset);
            startOffset -= startOffset % this.bytesPerRow;
            
            let output = '[OFFSET]   | [HEX] 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | [ASCII]\n';
            output += '-'.repeat(75) + '\n';
            
            const endRow = Math.min(startOffset + numRows * this.bytesPerRow, this.data.length);
            
            for (let offset = startOffset; offset < endRow; offset += this.bytesPerRow) {
                const chunkLen = Math.min(this.bytesPerRow, this.data.length - offset);
                const chunk = this.data.subarray(offset, offset + chunkLen);
                
                const offsetStr = offset.toString(16).padStart(8, '0').toUpperCase();
                let hexStr = '';
                let asciiStr = '';
                
                for (let i = 0; i < this.bytesPerRow; i++) {
                    if (i === 8) hexStr += ' ';
                    
                    if (i < chunkLen) {
                        const byte = chunk[i];
                        const bStr = byte.toString(16).padStart(2, '0').toUpperCase();
                        const isHighlighted = highlightOffsets.includes(offset + i);
                        
                        if (isHighlighted) {
                            hexStr += `[HIGHLIGHT]${bStr}[/HIGHLIGHT] `;
                        } else {
                            hexStr += `${bStr} `;
                        }
                        
                        asciiStr += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    } else {
                        hexStr += '   ';
                        asciiStr += ' ';
                    }
                }
                
                output += `[OFFSET]${offsetStr}[/OFFSET] | ${hexStr.trimEnd()} | [ASCII]${asciiStr}[/ASCII]\n`;
            }
            
            return output;
        }
    }

    return HexViewer;
});
