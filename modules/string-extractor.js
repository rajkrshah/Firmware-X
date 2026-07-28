(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.StringExtractor = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    /**
     * @class StringExtractor
     * Extracts and classifies strings from binary data.
     */
    const StringExtractor = {
        /**
         * Extracts raw strings from a binary buffer.
         * @param {Uint8Array} uint8Array - Binary data.
         * @param {Object} options - Extraction options.
         * @returns {Array} List of extracted strings.
         */
        extract(uint8Array, options = {}) {
            if (!(uint8Array instanceof Uint8Array)) throw new Error("Input must be a Uint8Array");
            
            const minLength = options.minLength || 4;
            const includeOffset = options.includeOffset !== false;
            const encodings = Array.isArray(options.encoding) ? options.encoding : [options.encoding || 'ascii'];
            
            const results = [];
            
            if (encodings.includes('ascii')) {
                let currentStr = '';
                let currentOffset = -1;
                
                for (let i = 0; i < uint8Array.length; i++) {
                    const b = uint8Array[i];
                    if (b >= 32 && b <= 126) {
                        if (currentStr.length === 0) currentOffset = i;
                        currentStr += String.fromCharCode(b);
                    } else {
                        if (currentStr.length >= minLength) {
                            results.push({
                                offset: includeOffset ? currentOffset : undefined,
                                string: currentStr,
                                encoding: 'ascii',
                                length: currentStr.length
                            });
                        }
                        currentStr = '';
                    }
                }
                if (currentStr.length >= minLength) {
                    results.push({
                        offset: includeOffset ? currentOffset : undefined,
                        string: currentStr,
                        encoding: 'ascii',
                        length: currentStr.length
                    });
                }
            }
            
            if (encodings.includes('utf16le')) {
                let currentStr = '';
                let currentOffset = -1;
                
                for (let i = 0; i < uint8Array.length - 1; i += 2) {
                    const b1 = uint8Array[i];
                    const b2 = uint8Array[i+1];
                    
                    if (b1 >= 32 && b1 <= 126 && b2 === 0) {
                        if (currentStr.length === 0) currentOffset = i;
                        currentStr += String.fromCharCode(b1);
                    } else {
                        if (currentStr.length >= minLength) {
                            results.push({
                                offset: includeOffset ? currentOffset : undefined,
                                string: currentStr,
                                encoding: 'utf16le',
                                length: currentStr.length
                            });
                        }
                        currentStr = '';
                    }
                }
                if (currentStr.length >= minLength) {
                    results.push({
                        offset: includeOffset ? currentOffset : undefined,
                        string: currentStr,
                        encoding: 'utf16le',
                        length: currentStr.length
                    });
                }
            }
            
            results.sort((a, b) => a.offset - b.offset);
            return results;
        },

        /**
         * Extracts and classifies strings.
         * @param {Uint8Array} uint8Array - Binary data.
         * @param {Object} options - Extraction options.
         * @returns {Array} List of classified strings.
         */
        extractWithPatterns(uint8Array, options = {}) {
            const strings = this.extract(uint8Array, options);
            
            return strings.map(item => {
                const str = item.string;
                let type = 'generic';
                
                if (/^(https?|ftp):\/\//i.test(str)) type = 'url';
                else if (/^(\/etc\/|\/dev\/|[a-zA-Z]:\\|\.\/|\.\.\/)/.test(str)) type = 'path';
                else if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(str)) type = 'email';
                else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(str)) type = 'ip';
                else if (/^v\d+\.\d+|version|build/i.test(str)) type = 'version';
                else if (/(password|passwd|secret|key|token|admin|root)/i.test(str)) type = 'credential';
                else if (/-----BEGIN|RSA|AES|SHA|certificate/i.test(str)) type = 'crypto';
                else if (/(error|warning|assert|debug|trace|log)/i.test(str)) type = 'debug';
                else if (/^[a-zA-Z_][a-zA-Z0-9_]*\s*\(/.test(str)) type = 'function';
                
                item.type = type;
                return item;
            });
        },

        /**
         * Searches for a specific string pattern.
         * @param {Uint8Array} uint8Array - Binary data.
         * @param {string} searchString - String to find.
         * @param {string} encoding - Encoding to search in.
         * @returns {Array} Occurrences.
         */
        search(uint8Array, searchString, encoding = 'ascii') {
            const extracted = this.extract(uint8Array, { minLength: searchString.length, encoding: [encoding] });
            return extracted.filter(item => item.string.includes(searchString)).map(item => ({
                offset: item.offset + item.string.indexOf(searchString),
                context: item.string
            }));
        },

        /**
         * Gets statistics from extracted strings.
         * @param {Array} results - Extracted strings list.
         * @returns {Object} Stats object.
         */
        getStats(results) {
            const stats = {
                total: results.length,
                byType: {},
                byEncoding: {}
            };
            
            results.forEach(item => {
                if (item.type) {
                    stats.byType[item.type] = (stats.byType[item.type] || 0) + 1;
                }
                stats.byEncoding[item.encoding] = (stats.byEncoding[item.encoding] || 0) + 1;
            });
            
            return stats;
        }
    };

    return StringExtractor;
});
