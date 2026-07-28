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
        this.entropy = this.calculateEntropy(data);
        this.scanSignatures(data);
        this.detectWeakXOR(data);
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
        for (let i = 0; i < data.length - 4; i++) {
            if (data[i] === 0x63 && data[i+1] === 0x7c && data[i+2] === 0x77 && data[i+3] === 0x7b) {
                this.findings.push({
                    type: "Cryptographic Constant",
                    name: "AES S-Box Detected",
                    description: "Detected standard Rijndael (AES) S-Box constants. The firmware performs AES operations.",
                    offset: `0x${i.toString(16)}`
                });
                break;
            }
        }
    }

    detectWeakXOR(data) {
        if (data.length < 1024) return;
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
                this.assessment = `The firmware yields high entropy, but known compression/filesystem headers were detected. This indicates the firmware is packed or compressed rather than fully encrypted. <b>Decryption Feasibility: N/A (Compressed).</b> Proceed to extract the underlying filesystem using standard reverse-engineering tools (e.g. binwalk, unsquashfs).`;
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
        
        // Always append the extraction button so users can run binwalk on any firmware
        this.assessment += `<br><br><button class="btn btn-primary" onclick="window.app.extractFirmware()" style="margin-top: 10px;">Extract via CLI (binwalk)</button>`;
    }
}

class FirmwareAnalyzer {
    constructor() {
        // Safely init modules — if any fail, the UI still works
        try { this.fileDetector = typeof FileDetector !== 'undefined' ? new FileDetector() : { detect: () => null }; } catch(e) { this.fileDetector = { detect: () => null }; console.warn('FileDetector init failed:', e); }
        try { this.archiveExtractor = typeof ArchiveExtractor !== 'undefined' ? new ArchiveExtractor(typeof fflate !== 'undefined' ? fflate : null, typeof JSZip !== 'undefined' ? JSZip : null) : null; } catch(e) { this.archiveExtractor = null; console.warn('ArchiveExtractor init failed:', e); }
        try { this.hexDecoder = typeof HexDecoder !== 'undefined' ? new HexDecoder() : null; } catch(e) { this.hexDecoder = null; console.warn('HexDecoder init failed:', e); }
        try { this.layerEngine = typeof LayerEngine !== 'undefined' ? new LayerEngine(this.fileDetector, this.archiveExtractor, this.hexDecoder) : null; } catch(e) { this.layerEngine = null; console.warn('LayerEngine init failed:', e); }
        try { this.binaryParser = typeof BinaryParser !== 'undefined' ? new BinaryParser() : null; } catch(e) { this.binaryParser = null; console.warn('BinaryParser init failed:', e); }
        try { this.entropyAnalyzer = typeof EntropyAnalyzer !== 'undefined' ? EntropyAnalyzer : { analyze: () => ({ average: 0, max: 0, blocks: [] }) }; } catch(e) { this.entropyAnalyzer = { analyze: () => ({ average: 0, max: 0, blocks: [] }) }; console.warn('EntropyAnalyzer init failed:', e); }
        try { this.stringExtractor = typeof StringExtractor !== 'undefined' ? StringExtractor : { extract: () => [] }; } catch(e) { this.stringExtractor = { extract: () => [] }; console.warn('StringExtractor init failed:', e); }
        
        const hexContainer = document.getElementById('hex-container');
        try { this.hexViewer = typeof HexViewer !== 'undefined' && hexContainer ? new HexViewer(hexContainer) : null; } catch(e) { this.hexViewer = null; console.warn('HexViewer init failed:', e); }
        this.disassembler = null;
        try { this.encryptionAnalyzer = typeof EncryptionAnalyzer !== 'undefined' ? new EncryptionAnalyzer() : null; } catch(e) { this.encryptionAnalyzer = null; console.warn('EncryptionAnalyzer init failed:', e); }
        try { this.securityAnalyzer = typeof SecurityAnalyzer !== 'undefined' ? new SecurityAnalyzer() : null; } catch(e) { this.securityAnalyzer = null; console.warn('SecurityAnalyzer init failed:', e); }
        
        // State
        this.currentFile = null;
        this.currentData = null;
        this.analysisResults = null;
        this.activeTab = 'overview';
        this.securityResults = null;
        this.pendingFile = null;
        
        // Bind methods
        this.init = this.init.bind(this);
        
        // Run init on DOMContentLoaded if not already loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', this.init);
        } else {
            this.init();
        }
    }
    
    init() {
        // Each setup is independent — wrap individually so one failure doesn't block others
        try { this.setupDropZone(); } catch(e) { console.error('setupDropZone failed:', e); }
        try { this.setupTabs(); } catch(e) { console.error('setupTabs failed:', e); }
        try { this.setupHexViewer(); } catch(e) { console.error('setupHexViewer failed:', e); }
        try { this.setupDisassembly(); } catch(e) { console.error('setupDisassembly failed:', e); }
        try { this.setupFlowDiagramUI(); } catch(e) { console.error('setupFlowDiagramUI failed:', e); }
        try { this.setupEncryptionAnalysis(); } catch(e) { console.error('setupEncryptionAnalysis failed:', e); }
        try { this.setupStrings(); } catch(e) { console.error('setupStrings failed:', e); }
        try { this.setupSecurity(); } catch(e) { console.error('setupSecurity failed:', e); }
        try { this.setupKeyboardShortcuts(); } catch(e) { console.error('setupKeyboardShortcuts failed:', e); }
        console.log('Firmware-X v1.0.0 initialized.');
    }
    
    setupDropZone() {
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const btnSelect = document.getElementById('btn-select-file');
        const btnStart = document.getElementById('btn-start');
        const fileInfo = document.getElementById('selected-file-info');
        const fileName = document.getElementById('selected-file-name');
        const fileSize = document.getElementById('selected-file-size');
        
        if (!dropZone || !fileInput) return;

        // Drag-and-drop handlers
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => { e.preventDefault(); e.stopPropagation(); }, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
        });

        // Drag-and-drop: select file (don't auto-start)
        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length) this.selectFile(files[0]);
        }, false);

        // Select File button
        if (btnSelect) {
            btnSelect.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.click();
            });
        }

        // File input change: select file
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) this.selectFile(e.target.files[0]);
        });

        // Start button: begin analysis
        if (btnStart) {
            btnStart.addEventListener('click', (e) => {
                e.stopPropagation();
                if (this.pendingFile) this.loadFile(this.pendingFile);
            });
        }
    }

    selectFile(file) {
        this.pendingFile = file;
        const fileInfo = document.getElementById('selected-file-info');
        const fileName = document.getElementById('selected-file-name');
        const fileSize = document.getElementById('selected-file-size');
        const btnStart = document.getElementById('btn-start');

        if (fileInfo) fileInfo.classList.remove('hidden');
        if (fileName) fileName.innerText = file.name;
        if (fileSize) fileSize.innerText = this.formatFileSize(file.size);
        if (btnStart) {
            btnStart.disabled = false;
            btnStart.classList.add('ready');
        }
    }

    setupTabs() {
        const tabs = document.querySelectorAll('.tab-btn');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.getAttribute('data-target');
                this.showTab(target.replace('panel-', ''));
            });
        });
    }

    showTab(tabName) {
        const tabs = document.querySelectorAll('.tab-btn');
        const panels = document.querySelectorAll('.panel');
        
        tabs.forEach(tab => {
            if (tab.getAttribute('data-target') === `panel-${tabName}`) {
                tab.classList.add('active');
            } else {
                tab.classList.remove('active');
            }
        });
        
        panels.forEach(panel => {
            if (panel.id === `panel-${tabName}`) {
                panel.classList.add('active');
                panel.classList.add('slide-up');
            } else {
                panel.classList.remove('active');
                panel.classList.remove('slide-up');
            }
        });

        this.activeTab = tabName;

        // Resize hooks
        if (tabName === 'entropy' && this.currentData) {
            this.drawEntropyChart();
        }
    }

    setupHexViewer() {
        const btnGoto = document.getElementById('btn-goto');
        if (btnGoto) {
            btnGoto.addEventListener('click', () => {
                const val = document.getElementById('hex-goto').value;
                if (this.hexViewer && val) this.hexViewer.scrollToOffset(parseInt(val, 16) || 0);
            });
        }
        const btnSearch = document.getElementById('btn-hex-search');
        if (btnSearch) {
            btnSearch.addEventListener('click', () => {
                const val = document.getElementById('hex-search').value;
                if (this.hexViewer && val) {
                    const isHex = /^[0-9a-fA-F\s]+$/.test(val);
                    const results = this.hexViewer.search(val, isHex, 0);
                    if (results.length > 0) {
                        this.hexViewer.scrollToOffset(results[0].offset);
                        // Store full results state if needed, or highlight them
                        this.hexViewer.setHighlights(results.map(r => r.offset)); // simple highlight
                    } else {
                        alert("Pattern not found.");
                    }
                }
            });
        }
    }

    setupDisassembly() {
        const btnDisasm = document.getElementById('btn-disassemble');
        if (btnDisasm) {
            btnDisasm.addEventListener('click', () => {
                const arch = document.getElementById('disasm-arch').value;
                const mode = document.getElementById('disasm-mode').value;
                this.runDisassembly(arch, mode, false);
            });
        }
        
        const btnDisasmSearch = document.getElementById('btn-disasm-search');
        if (btnDisasmSearch) {
            btnDisasmSearch.addEventListener('click', () => {
                const query = document.getElementById('disasm-search').value.toLowerCase();
                const container = document.getElementById('disasm-container');
                if (!container || !query) return;
                
                const rows = container.querySelectorAll('.disasm-row');
                let found = false;
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    if (text.includes(query)) {
                        if (!found) {
                            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            found = true;
                        }
                        row.style.backgroundColor = 'rgba(52, 152, 219, 0.4)'; // Highlight
                    } else {
                        row.style.backgroundColor = ''; // Reset
                    }
                });
                
                if (!found) {
                    alert("Text not found in disassembly.");
                }
            });
        }
        
        const btnDisasmFull = document.getElementById('btn-disassemble-full');
        if (btnDisasmFull) {
            btnDisasmFull.addEventListener('click', async () => {
                if (!this.currentData) {
                    alert("No firmware loaded.");
                    return;
                }
                const arch = document.getElementById('disasm-arch').value;
                const mode = document.getElementById('disasm-mode').value;
                
                btnDisasmFull.innerText = "Loading Capstone Engine...";
                btnDisasmFull.disabled = true;
                try {
                    // Load the same capstone-wasm CDN module used by the preview Disassemble button
                    const capstoneModule = await import('https://cdn.jsdelivr.net/npm/capstone-wasm@1.0.3/+esm');
                    await capstoneModule.loadCapstone();
                    const Capstone = capstoneModule.Capstone;
                    const cs = capstoneModule.Const;

                    // Map dropdown values to capstone constants
                    let archId = cs.CS_ARCH_X86;
                    let modeId = cs.CS_MODE_32;
                    
                    if (arch === 'arm') archId = cs.CS_ARCH_ARM;
                    else if (arch === 'arm64') archId = cs.CS_ARCH_ARM64;
                    else if (arch === 'mips') archId = cs.CS_ARCH_MIPS;
                    else if (arch === 'ppc') archId = cs.CS_ARCH_PPC;
                    else if (arch === 'sparc') archId = cs.CS_ARCH_SPARC;
                    else if (arch === 'm68k') archId = cs.CS_ARCH_M68K;

                    if (mode === '16') modeId = cs.CS_MODE_16;
                    else if (mode === '32') modeId = cs.CS_MODE_32;
                    else if (mode === '64') modeId = cs.CS_MODE_64;
                    else if (mode === 'thumb') modeId = cs.CS_MODE_THUMB;
                    else if (mode === 'arm') modeId = cs.CS_MODE_ARM;
                    else if (mode === 'mips32') modeId = cs.CS_MODE_MIPS32;
                    else if (mode === 'mips64') modeId = cs.CS_MODE_MIPS64;
                    else if (mode === 'v8') modeId = cs.CS_MODE_V8;
                    else if (mode === 'v9') modeId = cs.CS_MODE_V9;
                    else if (mode === 'default') modeId = 0;

                    const CHUNK_SIZE = 8192;
                    let currentOffset = 0;
                    let blobParts = [];
                    const data = this.currentData;
                    
                    btnDisasmFull.innerText = "Disassembling... 0%";
                    
                    const processChunk = () => {
                        // Process multiple chunks per UI frame for speed
                        for (let i = 0; i < 5 && currentOffset < data.length; i++) {
                            const safeLen = Math.min(CHUNK_SIZE, data.length - currentOffset);
                            const chunk = data.slice(currentOffset, currentOffset + safeLen);
                            
                            let bytesDecoded = 0;
                            try {
                                const disassembler = new Capstone(archId, modeId);
                                const instructions = disassembler.disasm(chunk, { address: currentOffset, count: 5000 });
                                
                                let outText = '';
                                if (instructions && instructions.length > 0) {
                                    for (const insn of instructions) {
                                        const bytesHex = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(24, ' ');
                                        outText += `0x${insn.address.toString(16).padStart(8, '0')}:  ${bytesHex} ${insn.mnemonic}\t${insn.opStr}\n`;
                                        bytesDecoded += insn.bytes.length;
                                    }
                                }
                                blobParts.push(outText);
                                disassembler.close();
                            } catch (chunkErr) {
                                // Skip this chunk on error
                            }
                            
                            currentOffset += bytesDecoded > 0 ? bytesDecoded : safeLen;
                        }
                        
                        if (currentOffset < data.length) {
                            const percent = Math.floor((currentOffset / data.length) * 100);
                            btnDisasmFull.innerText = `Disassembling... ${percent}%`;
                            setTimeout(processChunk, 1);
                        } else {
                            // Done — trigger file download
                            const blob = new Blob(blobParts, { type: 'text/plain' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `firmware_${arch || 'auto'}.asm`;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                            URL.revokeObjectURL(url);
                            
                            btnDisasmFull.innerText = "Download Full .asm";
                            btnDisasmFull.disabled = false;
                        }
                    };
                    
                    processChunk();
                    
                } catch (e) {
                    alert("Error during disassembly: " + e.message);
                    btnDisasmFull.innerText = "Download Full .asm";
                    btnDisasmFull.disabled = false;
                }
            });
        }
        
        const disasmContainer = document.getElementById('disasm-container');
        if (disasmContainer) {
            disasmContainer.addEventListener('click', (e) => {
                if (e.target && e.target.id === 'btn-load-more-disasm') {
                    const arch = document.getElementById('disasm-arch').value;
                    const mode = document.getElementById('disasm-mode').value;
                    this.runDisassembly(arch, mode, true);
                }
            });
        }
        
        const archSelect = document.getElementById('disasm-arch');
        const modeSelect = document.getElementById('disasm-mode');
        if (archSelect && modeSelect) {
            const updateModes = () => {
                const arch = archSelect.value;
                let modes = [];
                switch(arch) {
                    case 'x86': modes = [{v:'16',t:'16-bit'}, {v:'32',t:'32-bit', s:true}, {v:'64',t:'64-bit'}]; break;
                    case 'arm': modes = [{v:'arm',t:'ARM', s:true}, {v:'thumb',t:'Thumb'}]; break;
                    case 'arm64': modes = [{v:'default',t:'Default (64-bit)'}]; break;
                    case 'mips': modes = [{v:'mips32',t:'MIPS32', s:true}, {v:'mips64',t:'MIPS64'}, {v:'micromips',t:'MicroMIPS'}]; break;
                    case 'ppc': modes = [{v:'32',t:'32-bit', s:true}, {v:'64',t:'64-bit'}]; break;
                    case 'sparc': modes = [{v:'v8',t:'V8 (32-bit)'}, {v:'v9',t:'V9'}]; break;
                    case 'm68k': modes = [{v:'68000',t:'68000', s:true}, {v:'68010',t:'68010'}, {v:'68020',t:'68020'}, {v:'68030',t:'68030'}, {v:'68040',t:'68040'}, {v:'68060',t:'68060'}]; break;
                    default: modes = [{v:'default',t:'Default', s:true}]; break;
                }
                modeSelect.innerHTML = modes.map(m => `<option value="${m.v}" ${m.s ? 'selected' : ''}>${m.t}</option>`).join('');
            };
            archSelect.addEventListener('change', updateModes);
            // init
            updateModes();
        }

        const btnAuto = document.getElementById('btn-autodetect-arch');
        if (btnAuto) {
            btnAuto.addEventListener('click', () => {
                if (!this.currentData || !this.binaryParser) {
                    alert("No binary loaded or parser unavailable.");
                    return;
                }
                const info = this.binaryParser.getArchitectureInfo(this.currentData);
                if (!info) {
                    alert("Could not auto-detect architecture from header (unsupported or raw binary).");
                    return;
                }
                
                let detectedArch = 'x86';
                let detectedMode = info.mode === 64 ? '64' : '32';
                
                const archStr = info.arch.toLowerCase();
                if (archStr.includes('arm 64') || archStr.includes('aarch64')) {
                    detectedArch = 'arm64';
                    detectedMode = 'default';
                } else if (archStr.includes('arm')) {
                    detectedArch = 'arm';
                    detectedMode = 'arm';
                } else if (archStr.includes('mips')) {
                    detectedArch = 'mips';
                    detectedMode = info.mode === 64 ? 'mips64' : 'mips32';
                } else if (archStr.includes('powerpc') || archStr.includes('ppc')) {
                    detectedArch = 'ppc';
                    detectedMode = info.mode === 64 ? '64' : '32';
                } else if (archStr.includes('sparc')) {
                    detectedArch = 'sparc';
                    detectedMode = 'v8';
                } else if (archStr.includes('68000') || archStr.includes('m68k')) {
                    detectedArch = 'm68k';
                    detectedMode = '68000';
                } else if (archStr.includes('x86-64') || archStr.includes('amd64')) {
                    detectedArch = 'x86';
                    detectedMode = '64';
                } else if (archStr.includes('80386') || archStr.includes('x86')) {
                    detectedArch = 'x86';
                    detectedMode = '32';
                }
                
                if (archSelect) {
                    archSelect.value = detectedArch;
                    archSelect.dispatchEvent(new Event('change')); // Triggers mode dropdown refresh
                }
                if (modeSelect) {
                    modeSelect.value = detectedMode;
                }
                const endian = document.getElementById('disasm-endian');
                if (endian) {
                    endian.value = info.endian.toLowerCase().includes('big') ? 'big' : 'little';
                }
                
                this.updateProgress(`Auto-detected: ${info.arch} (${info.mode}-bit)`, 100);
                setTimeout(() => this.updateProgress('Ready', 0), 3000);
            });
        }
    }

    setupFlowDiagramUI() {
        const btnFlow = document.getElementById('btn-flow-diagram');
        
        if (btnFlow) {
            btnFlow.addEventListener('click', () => {
                this.renderFlowDiagram();
            });
        }
    }
    
    async renderFlowDiagram() {
        if (!this.currentInstructions || this.currentInstructions.length === 0) {
            alert("No instructions available to graph.");
            return;
        }
        
        document.getElementById('btn-flow-diagram').innerText = "Generating...";
        
        try {
            // Basic Block partitioning
            let leaders = new Set();
            leaders.add(this.currentInstructions[0].address); // First instruction is a leader
            
            // Pass 1: Find branch targets and following instructions
            for (let i = 0; i < this.currentInstructions.length; i++) {
                const ins = this.currentInstructions[i];
                const mnem = ins.mnemonic.toLowerCase();
                
                if (mnem.startsWith('j') || mnem.startsWith('b') || mnem === 'call') {
                    // Try to parse target address from opStr
                    const match = ins.opStr.match(/0x[0-9a-fA-F]+/);
                    if (match) {
                        leaders.add(parseInt(match[0], 16));
                    }
                    if (i + 1 < this.currentInstructions.length) {
                        leaders.add(this.currentInstructions[i+1].address);
                    }
                }
            }
            
            let blocks = {}; // address -> string
            let currentLeader = null;
            let currentBlockLines = [];
            
            // Pass 2: Partition blocks
            let context = { lastCmp: null };
            for (let i = 0; i < this.currentInstructions.length; i++) {
                const ins = this.currentInstructions[i];
                if (leaders.has(ins.address)) {
                    if (currentLeader !== null) {
                        blocks[currentLeader] = currentBlockLines;
                    }
                    currentLeader = ins.address;
                    currentBlockLines = [];
                }
                const pseudo = this.generatePseudoC(ins.mnemonic, ins.opStr, context);
                currentBlockLines.push({
                    addr: ins.address,
                    mnem: ins.mnemonic,
                    opStr: ins.opStr,
                    pseudoC: pseudo
                });
            }
            if (currentLeader !== null) {
                blocks[currentLeader] = currentBlockLines;
            }
            
            // Pass 3: Draw edges
            let mermaidStr = 'graph TD\n';
            
            const leaderArray = Object.keys(blocks).map(k => parseInt(k, 10)).sort((a,b) => a - b);
            
            for (let i = 0; i < leaderArray.length; i++) {
                const addr = leaderArray[i];
                const blockInsts = blocks[addr];
                
                let pseudoLines = blockInsts.map(inst => {
                    const addrStr = `0x${inst.addr.toString(16)}`;
                    const asmStr = `${inst.mnem} ${inst.opStr}`;
                    const line = inst.pseudoC ? `${addrStr}: ${asmStr} => ${inst.pseudoC}` : `${addrStr}: ${asmStr}`;
                    return line.replace(/["<>]/g, '');
                });
                
                // Wrap lines > 55 chars to keep boxes closer to square
                pseudoLines = pseudoLines.map(line => {
                    if (line.length > 55) {
                        return line.match(/.{1,55}(\s|$)/g).join('<br/>');
                    }
                    return line;
                });
                
                let nodeText = pseudoLines.join('<br/>');
                if (nodeText.length > 800) nodeText = nodeText.substring(0, 800) + '<br/>...';
                
                mermaidStr += `  B_${addr}["${nodeText}"]\n`;
                
                // determine edge based on last instruction in block
                const lastInst = blockInsts[blockInsts.length - 1];
                const mnem = lastInst.mnem.toLowerCase();
                const opStr = lastInst.opStr.toLowerCase();
                
                if (mnem.startsWith('ret')) {
                    // No outgoing edge
                } else if (mnem === 'jmp' || mnem === 'b') {
                    // Unconditional jump
                    const match = opStr.match(/0x[0-9a-f]+/);
                    if (match) {
                        const target = parseInt(match[0], 16);
                        if (blocks[target]) mermaidStr += `  B_${addr} --> B_${target}\n`;
                    }
                } else if (mnem.startsWith('j') || mnem.startsWith('b')) {
                    // Conditional jump
                    const match = opStr.match(/0x[0-9a-f]+/);
                    if (match) {
                        const target = parseInt(match[0], 16);
                        if (blocks[target]) mermaidStr += `  B_${addr} -->|True| B_${target}\n`;
                    }
                    if (i + 1 < leaderArray.length) {
                        mermaidStr += `  B_${addr} -->|False| B_${leaderArray[i+1]}\n`;
                    }
                } else {
                    // sequential
                    if (i + 1 < leaderArray.length) {
                        mermaidStr += `  B_${addr} --> B_${leaderArray[i+1]}\n`;
                    }
                }
            }
            const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Function Flow Diagram</title>
    <style>
        body { margin: 0; padding: 0; background: #0f172a; color: #fff; font-family: sans-serif; overflow: hidden; }
        #container { width: 100vw; height: 100vh; display: flex; justify-content: center; align-items: center; }
        .loading { font-size: 1.2rem; color: #a855f7; }
        svg { max-width: none !important; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/dist/svg-pan-zoom.min.js"><\/script>
</head>
<body>
    <div id="container"><div class="loading">Rendering Flow Diagram...</div></div>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        
        mermaid.initialize({ 
            startOnLoad: false, 
            theme: 'dark', 
            securityLevel: 'loose',
            themeVariables: {
                fontSize: '22px',
                fontFamily: 'monospace'
            }
        });
        
        const graphDefinition = \`${mermaidStr.replace(/`/g, '\\`')}\`;
        
        async function render() {
            try {
                const { svg } = await mermaid.render('mermaid-svg', graphDefinition);
                const container = document.getElementById('container');
                container.innerHTML = svg;
                
                const svgElement = container.querySelector('svg');
                svgElement.style.width = '100%';
                svgElement.style.height = '100%';
                
                if (window.svgPanZoom) {
                    window.svgPanZoom(svgElement, {
                        zoomEnabled: true,
                        controlIconsEnabled: true,
                        fit: true,
                        center: true,
                        minZoom: 0.1,
                        maxZoom: 100
                    });
                }
            } catch(e) {
                document.getElementById('container').innerHTML = '<div style="color:red; padding:20px;">Error rendering graph: ' + e.message + '</div>';
            }
        }
        render();
    <\/script>
</body>
</html>`;

            const newWin = window.open('', '_blank');
            if (!newWin) {
                alert('Popup blocked. Please allow popups for this site to view the Flow Diagram.');
            } else {
                newWin.document.write(htmlContent);
                newWin.document.close();
            }
            
        } catch (e) {
            console.error("Flow diagram error:", e);
            alert("Error generating diagram: " + e.message);
        } finally {
            document.getElementById('btn-flow-diagram').innerText = "View Flow Diagram";
        }
    }

    setupEncryptionAnalysis() {
        // UI is automated on load, no setup required.
    }

    setupStrings() {
        const slider = document.getElementById('string-min-len');
        const chkUrl = document.getElementById('chk-url');
        const chkPath = document.getElementById('chk-path');
        const chkCred = document.getElementById('chk-cred');
        const chkCrypto = document.getElementById('chk-crypto');
        const searchInput = document.getElementById('string-search');
        
        const triggerFilter = () => this.filterStrings();

        if (slider) {
            slider.addEventListener('input', (e) => {
                document.getElementById('string-len-val').innerText = e.target.value;
                triggerFilter();
            });
        }
        
        if (chkUrl) chkUrl.addEventListener('change', triggerFilter);
        if (chkPath) chkPath.addEventListener('change', triggerFilter);
        if (chkCred) chkCred.addEventListener('change', triggerFilter);
        if (chkCrypto) chkCrypto.addEventListener('change', triggerFilter);
        if (searchInput) searchInput.addEventListener('input', triggerFilter);
    }
    
    filterStrings() {
        if (!this.allStrings) return;
        
        const minLen = parseInt(document.getElementById('string-min-len').value) || 4;
        const showUrl = document.getElementById('chk-url').checked;
        const showPath = document.getElementById('chk-path').checked;
        const showCred = document.getElementById('chk-cred').checked;
        const showCrypto = document.getElementById('chk-crypto').checked;
        const query = (document.getElementById('string-search').value || '').toLowerCase();
        
        const filtered = this.allStrings.filter(s => {
            const text = s.text || s.string || '';
            if (text.length < minLen) return false;
            
            if (query && !text.toLowerCase().includes(query)) return false;
            
            // If all checkboxes are checked, show everything that matches above
            // But if user unchecked some, filter by type
            // To make it intuitive: if the type is one of the checkbox categories, check its state.
            // If it's a generic string or other type, we usually show it unless they specifically filter.
            // Let's implement exact type matching for the checkboxes:
            const t = s.type || 'generic';
            if (t === 'url' && !showUrl) return false;
            if (t === 'path' && !showPath) return false;
            if (t === 'credential' && !showCred) return false;
            if (t === 'crypto' && !showCrypto) return false;
            
            return true;
        });
        
        this.updateStrings(filtered);
    }

    setupKeyboardShortcuts() {
        window.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'o') {
                e.preventDefault();
                document.getElementById('file-input').click();
            }
        });
    }

    async loadFile(file) {
        this.currentFile = file;
        this.updateProgress('Reading file...', 10);
        
        document.getElementById('drop-zone').classList.add('hidden');
        document.getElementById('file-info-bar').classList.remove('hidden');
        document.getElementById('workspace').classList.remove('hidden');
        
        document.getElementById('info-filename').innerText = file.name;
        document.getElementById('info-size').innerText = this.formatFileSize(file.size);
        
        const reader = new FileReader();
        reader.onload = async (e) => {
            try {
                const buffer = e.target.result;
                this.currentData = new Uint8Array(buffer);
                
                this.updateProgress('Calculating SHA-256...', 30);
                const hash = await this.computeSHA256(this.currentData);
                document.getElementById('info-hash').innerText = file.size > 25 * 1024 * 1024 ? hash + " (First 25MB)" : hash;
                
                await this.runFullAnalysis(this.currentData, file.name);
            } catch (err) {
                console.error("Error in loadFile:", err);
                alert("Critical error loading file: " + err.message);
                this.updateProgress('Error loading file', 0);
            }
        };
        // 8GB+ Streaming Infrastructure: Only load the first 25MB into RAM for UI rendering!
        // The rest of the file is streamed natively from disk during backend extraction/scanning.
        const SLICE_SIZE = Math.min(file.size, 25 * 1024 * 1024);
        reader.readAsArrayBuffer(file.slice(0, SLICE_SIZE));
    }
    
    async runFullAnalysis(uint8Array, filename) {
        try {
            this.updateProgress('Detecting file type...', 40);
            let fileType = 'Unknown Binary';
            let detectResult = null;
            let signatures = [];
            if (this.fileDetector && this.fileDetector.detect) {
                detectResult = this.fileDetector.detect(uint8Array);
                if (detectResult && detectResult.name) fileType = detectResult.name;
                
                if (this.fileDetector.scanAll) {
                    signatures = this.fileDetector.scanAll(uint8Array);
                }
            }
            
            document.getElementById('info-type').innerText = fileType;
            document.getElementById('stat-type').innerText = fileType;
            document.getElementById('stat-size').innerText = this.formatFileSize(uint8Array.length);
            
            this.updateMetadata(filename, uint8Array.length, detectResult, signatures);

            this.updateProgress('Analyzing layers...', 50);
            let rootLayer = null;
            if (this.layerEngine && this.layerEngine.analyze) {
                rootLayer = await this.layerEngine.analyze(uint8Array, filename);
            }
            
            // Append ELF/PE sections to layers tree so structure is visible
            if (rootLayer && this.binaryParser) {
                const info = this.binaryParser.getArchitectureInfo(uint8Array);
                if (info) {
                    if (uint8Array[0] === 0x7F && uint8Array[1] === 0x45) {
                        const elf = this.binaryParser.parseELF(uint8Array);
                        if (elf && elf.sectionHeaders) {
                            elf.sectionHeaders.forEach(sh => {
                                if (sh.name) {
                                    rootLayer.children.push({
                                        name: `Section: ${sh.name}`,
                                        type: 'elf-section',
                                        size: sh.size,
                                        children: []
                                    });
                                }
                            });
                        }
                    }
                }
            }

            // Run Encryption Analysis
            if (this.encryptionAnalyzer) {
                this.updateProgress('Running Encryption Analysis...', 60);
                try {
                    const encResults = await this.encryptionAnalyzer.analyze(uint8Array);
                    this.renderEncryptionResults(encResults);
                } catch (e) {
                    alert("Error inside encryptionAnalyzer: " + e.message + "\n" + e.stack);
                }
            } else {
                alert("WARNING: this.encryptionAnalyzer is null! The module failed to initialize.");
            }
            
            this.updateLayers(rootLayer);

            this.updateProgress('Analyzing entropy...', 60);
            if (this.entropyAnalyzer && this.entropyAnalyzer.analyze) {
                const entropyResult = this.entropyAnalyzer.analyze(uint8Array, parseInt(document.getElementById('entropy-block-size').value || '1024'));
                this.updateEntropy(entropyResult);
            }

            this.updateProgress('Extracting strings...', 80);
            if (this.stringExtractor && this.stringExtractor.extract) {
                const strings = this.stringExtractor.extract(uint8Array, 4);
                this.allStrings = strings; // store for filtering
                this.updateStrings(strings);
            }

            if (this.hexViewer && this.hexViewer.setData) {
                this.hexViewer.setData(uint8Array);
                this.hexViewer.render(0, 1024); // Render first 1024 rows (~16KB)
            } else {
                this.mockHexView(uint8Array);
            }

            this.updateProgress('Running security analysis...', 90);
            if (this.securityAnalyzer && this.securityAnalyzer.analyze) {
                const securityResult = this.securityAnalyzer.analyze(uint8Array);
                this.securityResults = securityResult;
                this.updateSecurity(securityResult);
            }

            this.updateProgress('Analysis complete.', 100);
            setTimeout(() => this.updateProgress('Ready', 0), 2000);
        } catch (e) {
            console.error(e);
            alert("Error during analysis: " + e.message + "\n\n" + e.stack);
            this.updateProgress('Error during analysis', 0);
        }
    }

    async extractFirmware() {
        if (!this.currentData || !this.currentFile) {
            alert("No firmware loaded.");
            return;
        }
        
        const outputConsole = document.getElementById('enc-output-console');
        if (outputConsole) {
            outputConsole.innerHTML = `<span style="color:var(--accent-magenta);">[System]</span> Streaming firmware to backend for Binwalk extraction...<br>`;
        }
        this.updateProgress('Uploading binary to backend for extraction...', 10);
        
        try {
            const bodyData = this.currentFile;
            
            const response = await fetch('/api/extract', {
                method: 'POST',
                headers: {
                    'X-File-Name': this.currentFile.name
                },
                body: bodyData
            });
            
            const result = await response.json();
            if (response.ok) {
                this.updateProgress('Extraction launched!', 100);
                if (outputConsole) {
                    outputConsole.innerHTML = result.output.replace(/\\n/g, '<br>').replace(/\[System\]/g, '<span style="color:var(--accent-cyan);">[System]</span>');
                }
                alert(`Extraction Launched Successfully!\\n\\n${result.output.replace(/\\n/g, '\\n')}\\n\\nCheck the terminal window that just opened.`);
            } else {
                this.updateProgress('Extraction failed.', 0);
                const errMsg = result.error || 'Unknown error';
                if (outputConsole) {
                    outputConsole.innerHTML = `<span style="color:red;">[Error]</span> ${errMsg}<br>${(result.output || '').replace(/\\n/g, '<br>')}`;
                }
                alert(`Extraction Failed:\\n${errMsg}\\n\\n${result.output || ''}`);
            }
        } catch (e) {
            this.updateProgress('Extraction error.', 0);
            alert(`Error triggering extraction: ${e.message}\\n\\nMake sure the Node.js server is running (node server.js).`);
        }
    }

    updateMetadata(filename, size, detectResult, signatures) {
        const tbody = document.getElementById('metadata-tbody');
        if (!tbody) return;
        
        const hash = document.getElementById('info-hash') ? document.getElementById('info-hash').innerText : 'N/A';
        
        let html = '';
        html += `<tr><td><strong>Filename</strong></td><td>${this.escapeHtml(filename)}</td></tr>`;
        html += `<tr><td><strong>Size</strong></td><td>${this.formatFileSize(size)} (${size} bytes)</td></tr>`;
        html += `<tr><td><strong>SHA-256</strong></td><td class="mono" style="font-size:0.85em">${hash}</td></tr>`;
        
        if (detectResult) {
            html += `<tr><td><strong>Primary Type</strong></td><td>${detectResult.name} (${detectResult.description})</td></tr>`;
        }
        
        if (signatures && signatures.length > 0) {
            html += `<tr><td colspan="2" style="background: rgba(255,255,255,0.05); text-align: center; color: var(--accent-blue);"><strong>Embedded Signatures Found</strong></td></tr>`;
            // Limit to 50 signatures to prevent lag
            const limit = Math.min(signatures.length, 50);
            for (let i = 0; i < limit; i++) {
                const sig = signatures[i];
                html += `<tr>
                    <td><span class="badge">${sig.name}</span></td>
                    <td class="mono">Offset: 0x${sig.offset.toString(16).toUpperCase()}</td>
                </tr>`;
            }
            if (signatures.length > 50) {
                html += `<tr><td colspan="2" style="text-align: center; color: var(--text-muted); font-size: 0.8em;">... and ${signatures.length - 50} more signatures hidden.</td></tr>`;
            }
        } else {
            html += `<tr><td colspan="2" style="text-align: center; color: var(--text-muted);">No embedded signatures detected.</td></tr>`;
        }
        
        tbody.innerHTML = html;
    }

    updateLayers(rootLayer) {
        const totalLayers = rootLayer ? (this.layerEngine ? this.layerEngine.stats.totalLayers : 0) : 0;
        document.getElementById('stat-layers').innerText = totalLayers;
        
        const treeContainer = document.getElementById('layer-tree-container');
        if (!treeContainer) return;
        
        if (!rootLayer || (rootLayer.children && rootLayer.children.length === 0 && rootLayer.type === 'unknown')) {
            treeContainer.innerHTML = '<div style="padding: 20px; color: var(--text-muted);">No embedded layers detected in this firmware.</div>';
            return;
        }

        // Color map for layer type badges
        const typeColors = {
            'elf': '#e74c3c', 'pe': '#e74c3c', 'macho': '#e74c3c',
            'squashfs': '#2ecc71', 'jffs2': '#2ecc71', 'cramfs': '#2ecc71', 'ubifs': '#2ecc71', 'extfs': '#2ecc71',
            'zip': '#3498db', 'gzip': '#3498db', 'tar': '#3498db', '7z': '#3498db', 'rar': '#3498db',
            'lzma': '#9b59b6', 'xz': '#9b59b6', 'bzip2': '#9b59b6', 'zstd': '#9b59b6', 'lz4': '#9b59b6',
            'uimage': '#f39c12', 'fit': '#f39c12', 'android_boot': '#f39c12',
            'png': '#1abc9c', 'jpeg': '#1abc9c', 'gif': '#1abc9c', 'bmp': '#1abc9c', 'pdf': '#1abc9c',
            'luks': '#e74c3c', 'openssl': '#e74c3c',
            'elf-section': '#95a5a6'
        };

        const self = this;

        const buildTreeHtml = (layer, depth = 0) => {
            const indent = depth * 24;
            const typeName = (layer.type || 'unknown').toUpperCase();
            const badgeColor = typeColors[layer.type] || '#7f8c8d';
            const offsetHex = layer.offset !== undefined && layer.offset > 0
                ? '<span style="font-family: monospace; font-size: 0.75em; color: var(--accent-cyan); margin-left: 8px;">@ 0x' + layer.offset.toString(16).toUpperCase() + '</span>'
                : '';
            const desc = layer.metadata && layer.metadata.description
                ? '<span style="font-size: 0.75em; color: var(--text-muted); margin-left: 10px;">' + self.escapeHtml(layer.metadata.description) + '</span>'
                : '';
            const errBadge = layer.metadata && layer.metadata.extractionError
                ? '<span style="font-size: 0.7em; color: #e74c3c; margin-left: 6px;" title="' + self.escapeHtml(layer.metadata.extractionError) + '">⚠ Extract Error</span>'
                : '';
            const childCount = layer.children && layer.children.length > 0
                ? '<span style="font-size: 0.7em; color: var(--text-muted); margin-left: 6px;">(' + layer.children.length + ' children)</span>'
                : '';
            const arrow = layer.children && layer.children.length > 0 ? '▾ ' : '  ';

            let html = '<div class="layer-node" data-layer-id="' + (layer.id || '') + '" style="padding-left: ' + (indent + 10) + 'px; padding-top: 8px; padding-bottom: 8px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.15s;" onmouseover="this.style.background=\'rgba(52,152,219,0.1)\'" onmouseout="this.style.background=\'transparent\'">';
            html += '<span style="color: var(--text-muted); font-size: 0.85em;">' + arrow + '</span>';
            html += '<strong style="font-size: 0.9em;">' + self.escapeHtml(layer.name) + '</strong>';
            html += ' <span style="display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 0.7em; font-weight: bold; color: #fff; background: ' + badgeColor + ';">' + typeName + '</span>';
            html += offsetHex;
            html += ' <span style="font-size: 0.8em; color: var(--text-muted);">' + self.formatFileSize(layer.size || 0) + '</span>';
            html += childCount + errBadge;
            html += desc;
            html += '</div>';
            
            if (layer.children && layer.children.length > 0) {
                layer.children.forEach(child => {
                    html += buildTreeHtml(child, depth + 1);
                });
            }
            return html;
        };

        treeContainer.innerHTML = buildTreeHtml(rootLayer);

        // Wire up click handlers for layer details
        const detailsContent = document.getElementById('layer-details-content');
        if (detailsContent) {
            treeContainer.querySelectorAll('.layer-node').forEach(node => {
                node.addEventListener('click', () => {
                    const layerId = node.getAttribute('data-layer-id');
                    const layer = this.layerEngine ? this.layerEngine.getLayerById(layerId) : null;
                    if (layer) {
                        let detailHtml = '<table style="width:100%; font-size: 0.9em;">';
                        detailHtml += '<tr><td><strong>Name</strong></td><td>' + this.escapeHtml(layer.name) + '</td></tr>';
                        detailHtml += '<tr><td><strong>Type</strong></td><td>' + (layer.type || 'unknown').toUpperCase() + '</td></tr>';
                        detailHtml += '<tr><td><strong>Size</strong></td><td>' + this.formatFileSize(layer.size) + ' (' + (layer.size || 0) + ' bytes)</td></tr>';
                        if (layer.offset > 0) {
                            detailHtml += '<tr><td><strong>Offset</strong></td><td>0x' + layer.offset.toString(16).toUpperCase() + ' (' + layer.offset + ')</td></tr>';
                        }
                        if (layer.metadata) {
                            if (layer.metadata.description) detailHtml += '<tr><td><strong>Description</strong></td><td>' + this.escapeHtml(layer.metadata.description) + '</td></tr>';
                            if (layer.metadata.magicBytes) detailHtml += '<tr><td><strong>Magic Bytes</strong></td><td style="font-family:monospace;">' + this.escapeHtml(layer.metadata.magicBytes) + '</td></tr>';
                            if (layer.metadata.extractionError) detailHtml += '<tr><td><strong>Extract Error</strong></td><td style="color:#e74c3c;">' + this.escapeHtml(layer.metadata.extractionError) + '</td></tr>';
                        }
                        detailHtml += '<tr><td><strong>Children</strong></td><td>' + (layer.children ? layer.children.length : 0) + '</td></tr>';
                        detailHtml += '</table>';
                        detailsContent.innerHTML = detailHtml;
                    }

                    // Highlight selected node
                    treeContainer.querySelectorAll('.layer-node').forEach(n => n.style.borderLeft = '');
                    node.style.borderLeft = '3px solid var(--accent-cyan)';
                });
            });
        }
    }
    
    updateEntropy(result) {
        document.getElementById('stat-entropy').innerText = result.overall ? result.overall.toFixed(2) : '0.00';
        document.getElementById('entropy-avg').innerText = result.overall ? result.overall.toFixed(2) : '0.00';
        
        let maxEntropy = 0;
        if (result.blocks && result.blocks.length > 0) {
            for (let i = 0; i < result.blocks.length; i++) {
                if (result.blocks[i].entropy > maxEntropy) {
                    maxEntropy = result.blocks[i].entropy;
                }
            }
        }
        document.getElementById('entropy-max').innerText = maxEntropy ? maxEntropy.toFixed(2) : '0.00';
        
        this.entropyData = result;
        if (this.activeTab === 'entropy') {
            this.drawEntropyChart();
        }
    }

    drawEntropyChart() {
        if (!this.entropyData || !this.entropyData.blocks) return;
        const canvas = document.getElementById('entropy-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.parentElement.clientWidth;
        const height = canvas.parentElement.clientHeight || 300;
        canvas.width = width;
        canvas.height = height;

        ctx.clearRect(0, 0, width, height);
        const blocks = this.entropyData.blocks;
        const blockWidth = Math.max(1, width / blocks.length);
        
        blocks.forEach((blockObj, i) => {
            const val = blockObj.entropy;
            const x = i * blockWidth;
            const h = (val / 8) * height;
            const y = height - h;
            
            if (val > 7) ctx.fillStyle = '#ef4444';
            else if (val > 4) ctx.fillStyle = '#eab308';
            else ctx.fillStyle = '#3b82f6';
            
            ctx.fillRect(x, y, Math.ceil(blockWidth), h);
        });
    }

    updateStrings(strings) {
        const tbody = document.getElementById('strings-tbody');
        if (!tbody) return;
        document.getElementById('stat-strings').innerText = strings.length;
        
        let html = '';
        const limit = Math.min(strings.length, 1000); // Display limit
        for (let i = 0; i < limit; i++) {
            const s = strings[i];
            const text = s.text || s.string || '';
            const type = s.type || 'text';
            html += `<tr>
                <td class="mono" style="color: var(--accent-cyan);">0x${(s.offset || 0).toString(16).padStart(8, '0')}</td>
                <td class="mono">${this.escapeHtml(text)}</td>
                <td class="type-${type.toLowerCase()}">${type}</td>
                <td>${s.encoding || 'ascii'}</td>
                <td>${text.length}</td>
            </tr>`;
        }
        tbody.innerHTML = html;
    }

    mockHexView(data) {
        const container = document.getElementById('hex-container');
        if (!container) return;
        let html = '';
        const rows = Math.min(Math.ceil(data.length / 16), 100);
        for (let i = 0; i < rows; i++) {
            const offset = i * 16;
            const slice = data.slice(offset, offset + 16);
            let hex = '';
            let ascii = '';
            for (let j = 0; j < 16; j++) {
                if (j < slice.length) {
                    const b = slice[j];
                    hex += b.toString(16).padStart(2, '0') + ' ';
                    ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                } else {
                    hex += '   ';
                    ascii += ' ';
                }
            }
            html += `<div class="hex-row">
                <div class="hex-offset">${offset.toString(16).padStart(8, '0')}</div>
                <div class="hex-bytes">${hex}</div>
                <div class="hex-ascii">${this.escapeHtml(ascii)}</div>
            </div>`;
        }
        container.innerHTML = html;
    }
    
    generatePseudoC(mnemonic, opStr, context = {}) {
        if (!mnemonic) return "";
        const m = mnemonic.toLowerCase();
        let ops = opStr ? opStr.split(',').map(s => s.trim()) : [];
        
        // Enhance memory operands [eax + 0x10] -> *(uint32_t*)(eax + 0x10)
        ops = ops.map(op => {
            if (op.includes('[')) {
                let sizeCast = '';
                if (op.includes('byte ptr')) sizeCast = 'uint8_t*';
                else if (op.includes('word ptr')) sizeCast = 'uint16_t*';
                else if (op.includes('dword ptr')) sizeCast = 'uint32_t*';
                else if (op.includes('qword ptr')) sizeCast = 'uint64_t*';
                else sizeCast = 'void*';
                
                return op.replace(/.*ptr \[([^\]]+)\]/i, `*(${sizeCast})($1)`).replace(/\[([^\]]+)\]/i, `*(${sizeCast})($1)`);
            }
            return op;
        });

        if (m === 'nop') return '/* NOP */';
        if (m === 'mov' || m === 'ldr' || m === 'str' || m === 'movzx' || m === 'movsx') {
            if (ops.length >= 2) return `${ops[0]} = ${ops[1]};`;
            return '';
        }
        if (m === 'lea') {
            if (ops.length >= 2) return `${ops[0]} = &(${ops[1].replace(/^\*\([^\)]+\)\(([^\)]+)\)$/, '$1')});`;
        }
        if (m === 'add' || m === 'sub' || m === 'mul' || m === 'div' || m === 'xor' || m === 'and' || m === 'or' || m === 'shl' || m === 'shr') {
            if (ops.length >= 2) {
                const op = m === 'add' ? '+' : m === 'sub' ? '-' : m === 'mul' ? '*' : m === 'div' ? '/' : m === 'xor' ? '^' : m === 'and' ? '&' : m === 'or' ? '|' : m === 'shl' ? '<<' : '>>';
                if (ops.length === 3) return `${ops[0]} = ${ops[1]} ${op} ${ops[2]};`;
                return `${ops[0]} ${op}= ${ops[1]};`;
            }
        }
        if (m === 'inc') return `${ops[0]}++;`;
        if (m === 'dec') return `${ops[0]}--;`;
        
        if (m === 'cmp' || m === 'test') {
            if (ops.length >= 2) {
                context.lastCmp = { op1: ops[0], op2: ops[1] };
                return `/* cmp ${ops[0]}, ${ops[1]} */`;
            }
        }
        
        if (m.startsWith('j') || m.startsWith('b')) {
            // Unconditional jumps
            if (m === 'jmp' || m === 'b') return `goto ${ops[0]};`;
            
            // Conditional jumps
            let cond = '';
            let isEq = false;
            if (m === 'je' || m === 'jz' || m === 'beq') { cond = '=='; isEq = true; }
            else if (m === 'jne' || m === 'jnz' || m === 'bne') { cond = '!='; }
            else if (m === 'jg' || m === 'ja' || m === 'bgt') { cond = '>'; }
            else if (m === 'jl' || m === 'jb' || m === 'blt') { cond = '<'; }
            else if (m === 'jge' || m === 'bge') { cond = '>='; }
            else if (m === 'jle' || m === 'ble') { cond = '<='; }
            
            if (cond) {
                if (context.lastCmp) {
                    return `if (${context.lastCmp.op1} ${cond} ${context.lastCmp.op2}) goto ${ops[0]};`;
                }
                return `if (condition ${cond} 0) goto ${ops[0]};`;
            }
            return `goto ${ops[0]};`;
        }
        if (m === 'call' || m === 'bl') {
            return `${ops[0]}();`;
        }
        if (m === 'ret') {
            return 'return;';
        }
        if (m === 'push') return `push(${ops[0]});`;
        if (m === 'pop') return `${ops[0]} = pop();`;
        
        return `// ${m} ${opStr}`;
    }

    async runDisassembly(arch, mode, append = false) {
        const container = document.getElementById('disasm-container');
        if (!container) return;

        let fileOffset, baseAddr, maxCount;

        if (!append) {
            const offsetInput = document.getElementById('disasm-offset').value;
            const sizeInput = document.getElementById('disasm-size').value;
            const baseInput = document.getElementById('disasm-base') ? document.getElementById('disasm-base').value : '0';
            
            fileOffset = parseInt(offsetInput, 16);
            if (isNaN(fileOffset)) fileOffset = 0;
            
            baseAddr = parseInt(baseInput, 16);
            if (isNaN(baseAddr)) baseAddr = fileOffset;
            
            maxCount = parseInt(sizeInput, 10);
            if (isNaN(maxCount) || maxCount <= 0 || maxCount > 10000) maxCount = 2000;
            
            this.currentDisasmFileOffset = fileOffset;
            this.currentDisasmBaseAddr = baseAddr;
            this.currentDisasmCountSetting = maxCount;
            this.currentInstructions = [];
            
            container.innerHTML = '<div class="disasm-row"><div class="disasm-bytes">Loading Capstone-WASM engine from CDN...</div></div>';
        } else {
            fileOffset = this.currentDisasmFileOffset;
            baseAddr = this.currentDisasmBaseAddr;
            maxCount = this.currentDisasmCountSetting;
            const loadBtn = document.getElementById('btn-load-more-disasm');
            if (loadBtn) loadBtn.innerText = "Decompiling...";
        }
        
        try {
            const capstoneModule = await import('https://cdn.jsdelivr.net/npm/capstone-wasm@1.0.3/+esm');
            await capstoneModule.loadCapstone();
            const Capstone = capstoneModule.Capstone;
            const cs = capstoneModule.Const;

            let archId = cs.CS_ARCH_X86;
            let modeId = cs.CS_MODE_32;
            
            if (arch === 'arm') archId = cs.CS_ARCH_ARM;
            else if (arch === 'arm64') archId = cs.CS_ARCH_ARM64;
            else if (arch === 'mips') archId = cs.CS_ARCH_MIPS;
            else if (arch === 'ppc') archId = cs.CS_ARCH_PPC;
            else if (arch === 'sparc') archId = cs.CS_ARCH_SPARC;
            else if (arch === 'm68k') archId = cs.CS_ARCH_M68K;
            
            if (mode === '16') modeId = cs.CS_MODE_16;
            else if (mode === '32') modeId = cs.CS_MODE_32;
            else if (mode === '64') modeId = cs.CS_MODE_64;
            else if (mode === 'thumb') modeId = cs.CS_MODE_THUMB;
            else if (mode === 'arm') modeId = cs.CS_MODE_ARM;
            else if (mode === 'mips32') modeId = cs.CS_MODE_MIPS32;
            else if (mode === 'mips64') modeId = cs.CS_MODE_MIPS64;
            else if (mode === 'v8') modeId = cs.CS_MODE_V8;
            else if (mode === 'v9') modeId = cs.CS_MODE_V9;
            else if (mode === 'default') modeId = 0;

            if (!append) {
                container.innerHTML = '<div class="disasm-row"><div class="disasm-bytes">Analyzing binary with Capstone engine...</div></div>';
            }
            
            setTimeout(() => {
                try {
                    const disassembler = new Capstone(archId, modeId);
                    
                    const oldBtnRow = document.getElementById('load-more-row');
                    if (oldBtnRow) oldBtnRow.remove();
                    
                    const safeByteLength = Math.min(this.currentData.length - fileOffset, maxCount * 15);
                    const slice = this.currentData.slice(fileOffset, fileOffset + safeByteLength);
                    
                    const instructions = disassembler.disasm(slice, { address: baseAddr, count: maxCount });
                    
                    if (!instructions || instructions.length === 0) {
                        if (!append) {
                            container.innerHTML = '<div class="disasm-row"><div class="disasm-bytes" style="color:var(--text-muted)">No valid instructions found or data is not executable code for this architecture.</div></div>';
                            document.getElementById('disasm-count').innerText = "0";
                            document.getElementById('btn-flow-diagram').style.display = 'none';
                        } else {
                            container.insertAdjacentHTML('beforeend', '<div class="disasm-row"><div class="disasm-bytes" style="color:var(--text-muted); text-align:center;">Reached end of executable block.</div></div>');
                        }
                        disassembler.close();
                        return;
                    }
                    
                    this.currentInstructions = this.currentInstructions.concat(instructions);
                    
                    let decodedBytes = 0;
                    for (let i = 0; i < instructions.length; i++) {
                        decodedBytes += instructions[i].bytes.length;
                    }
                    this.currentDisasmFileOffset += decodedBytes;
                    this.currentDisasmBaseAddr += decodedBytes;
                    
                    document.getElementById('btn-flow-diagram').style.display = 'inline-block';

                    let html = '';
                    let pseudoCContext = {};
                    for(let i = 0; i < instructions.length; i++) {
                        const ins = instructions[i];
                        const bytesHex = Array.from(ins.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
                        const pseudoC = this.generatePseudoC(ins.mnemonic, ins.opStr, pseudoCContext);
                        
                        html += `<div class="disasm-row" style="display: flex;">
                            <div class="disasm-addr" style="flex: 0 0 100px;">0x${ins.address.toString(16).padStart(8, '0')}</div>
                            <div class="disasm-bytes" style="flex: 0 0 180px;">${bytesHex}</div>
                            <div class="disasm-mnem" style="flex: 0 0 80px;">${this.escapeHtml(ins.mnemonic)}</div>
                            <div class="disasm-ops" style="flex: 0 0 150px;">${this.escapeHtml(ins.opStr)}</div>
                            <div class="disasm-pseudo" style="flex: 1; border-left: 1px solid var(--border-color); padding-left: 10px; color: var(--accent-magenta); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${this.escapeHtml(pseudoC)}">${this.escapeHtml(pseudoC)}</div>
                        </div>`;
                    }
                    
                    if (append) {
                        container.insertAdjacentHTML('beforeend', html);
                    } else {
                        container.innerHTML = html;
                    }
                    
                    document.getElementById('disasm-count').innerText = this.currentInstructions.length.toString();
                    
                    if (instructions.length === maxCount && this.currentDisasmFileOffset < this.currentData.length) {
                        const btnHtml = `<div class="disasm-row" id="load-more-row" style="text-align:center; padding: 15px 0;">
                            <button id="btn-load-more-disasm" class="btn btn-secondary">Load Next Chunk</button>
                        </div>`;
                        container.insertAdjacentHTML('beforeend', btnHtml);
                    } else if (this.currentDisasmFileOffset >= this.currentData.length) {
                        container.insertAdjacentHTML('beforeend', `<div class="disasm-row" style="text-align:center; padding-top:10px; color:var(--severity-info)">Reached End of File.</div>`);
                    }
                    
                    disassembler.close();
                } catch (e) {
                    console.error("Disassembly error:", e);
                    container.innerHTML = `<div class="disasm-row"><div class="disasm-bytes" style="color:red">Disassembly failed: ${e.message}</div></div>`;
                }
            }, 50);

        } catch (e) {
            console.error("Capstone load error:", e);
            container.innerHTML = `<div class="disasm-row"><div class="disasm-bytes" style="color:red">Error loading Capstone-WASM: ${e.message}</div></div>`;
        }
    }
    renderEncryptionResults(results) {
        if (!results) return;
        
        const badge = document.getElementById('enc-status-badge');
        const subtitle = document.getElementById('enc-status-subtitle');
        const score = document.getElementById('enc-entropy-score');
        const assessment = document.getElementById('enc-assessment-text');
        const tbody = document.getElementById('enc-findings-body');
        
        if (badge) {
            badge.innerText = results.status;
            badge.className = `severity-badge ${results.statusClass}`;
        }
        if (subtitle) {
            subtitle.innerText = "Completed cryptographic analysis.";
        }
        if (score) {
            score.innerText = results.entropy.toFixed(2);
            if (results.entropy > 7.5) {
                score.style.color = "var(--severity-critical)";
            } else if (results.entropy > 6.0) {
                score.style.color = "var(--severity-medium)";
            } else {
                score.style.color = "var(--severity-info)";
            }
        }
        if (assessment) {
            assessment.innerHTML = results.assessment;
            // dynamic border color based on status
            if (results.statusClass === 'sev-critical') assessment.style.borderLeftColor = "var(--severity-critical)";
            if (results.statusClass === 'sev-high') assessment.style.borderLeftColor = "var(--severity-high)";
            if (results.statusClass === 'sev-medium') assessment.style.borderLeftColor = "var(--severity-medium)";
            if (results.statusClass === 'sev-info') assessment.style.borderLeftColor = "var(--severity-info)";
        }
        
        if (tbody) {
            if (results.findings.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No suspicious cryptographic structures detected.</td></tr>`;
            } else {
                tbody.innerHTML = results.findings.map(f => {
                    return `<tr>
                        <td style="font-weight: bold; color: var(--accent-magenta);">${this.escapeHtml(f.type)}</td>
                        <td>${this.escapeHtml(f.name)}</td>
                        <td class="mono">${this.escapeHtml(f.offset)}<br/><small style="color:var(--text-muted)">${this.escapeHtml(f.description)}</small></td>
                    </tr>`;
                }).join('');
            }
        }
    }

    async computeSHA256(data) {
        if (!crypto || !crypto.subtle) return 'Crypto API not available';
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    updateProgress(message, percent) {
        const msgEl = document.getElementById('status-msg');
        const barEl = document.getElementById('progress-bar');
        if (msgEl) msgEl.innerText = message;
        if (barEl) {
            barEl.style.width = percent + '%';
            if (percent === 0) {
                barEl.style.opacity = '0';
            } else {
                barEl.style.opacity = '1';
            }
        }
    }

    // ── Security Analysis ─────────────────────────────────────

    setupSecurity() {
        const sevFilter = document.getElementById('security-sev-filter');
        const catFilter = document.getElementById('security-cat-filter');
        const searchInput = document.getElementById('security-search');
        const exportHtmlBtn = document.getElementById('btn-export-html');
        const exportTxtBtn = document.getElementById('btn-export-txt');
        const scanBtn = document.getElementById('btn-scan-secrets');

        const applyFilters = () => {
            if (!this.securityResults) return;
            this.renderFindings(this.securityResults.findings);
        };

        if (sevFilter) sevFilter.addEventListener('change', applyFilters);
        if (catFilter) catFilter.addEventListener('change', applyFilters);
        if (searchInput) searchInput.addEventListener('input', applyFilters);
        
        // TXT Export
        if (exportTxtBtn) {
            exportTxtBtn.addEventListener('click', () => {
                if (!this.securityResults || !this.securityResults.findings) {
                    alert("No security findings to export.");
                    return;
                }
                
                const filename = this.currentFile ? this.currentFile.name : 'firmware';
                let txt = `Firmware-X Security Report\nFile: ${filename}\nRisk Score: ${this.securityResults.riskScore} / 10.0\n\nFindings:\n`;
                txt += "========================================================================\n\n";
                
                this.securityResults.findings.forEach((f, i) => {
                    txt += `[${i+1}] [${f.severity.toUpperCase()}] ${f.category}\n`;
                    txt += `Finding: ${f.name || f.title}\n`;
                    if (f.cwe) txt += `CWE: ${f.cwe}\n`;
                    txt += `Description: ${f.description}\n`;
                    if (f.offset !== undefined) txt += `Offset: 0x${f.offset.toString(16).toUpperCase()}\n`;
                    if (f.evidence) txt += `Evidence: ${f.evidence}\n`;
                    txt += "------------------------------------------------------------------------\n\n";
                });
                
                const blob = new Blob([txt], {type: 'text/plain'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security_report_${filename}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }

        // HTML Export
        if (exportHtmlBtn) {
            exportHtmlBtn.addEventListener('click', () => {
                if (!this.securityResults || !this.securityResults.findings) {
                    alert("No security findings to export.");
                    return;
                }
                
                const filename = this.currentFile ? this.currentFile.name : 'firmware';
                let html = `<!DOCTYPE html><html><head><title>Firmware-X Security Report</title>
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; color: #333; margin: 40px; }
                    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                    .summary { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
                    .finding { background: #fff; padding: 15px; border-left: 5px solid #333; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                    .sev-critical { border-color: #e74c3c; }
                    .sev-high { border-color: #e67e22; }
                    .sev-medium { border-color: #f1c40f; }
                    .sev-low { border-color: #3498db; }
                    .sev-info { border-color: #95a5a6; }
                    .badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 13px; font-weight: bold; color: white; margin-right: 10px; text-shadow: 1px 1px 1px rgba(0,0,0,0.3); }
                    .bg-critical { background-color: #e74c3c; }
                    .bg-high { background-color: #e67e22; }
                    .bg-medium { background-color: #f1c40f; color: #333; text-shadow: none; }
                    .bg-low { background-color: #3498db; }
                    .bg-info { background-color: #95a5a6; }
                    pre { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: monospace; }
                </style></head><body>
                <h1>Firmware-X Security Report</h1>
                <div class="summary">
                    <p><strong>Target File:</strong> ${filename}</p>
                    <p><strong>Total Findings:</strong> ${this.securityResults.findings.length}</p>
                    <p><strong>Risk Score (CVSS):</strong> ${this.securityResults.riskScore} / 10.0</p>
                </div>
                <h2>Detailed Findings</h2>
                `;
                
                this.securityResults.findings.forEach(f => {
                    const sev = f.severity || 'info';
                    html += `
                    <div class="finding sev-${sev}">
                        <h3 style="margin-top:0;"><span class="badge bg-${sev}">${sev.toUpperCase()}</span> ${f.name || f.title}</h3>
                        <p><strong>Category:</strong> ${f.category}</p>
                        ${f.cwe ? `<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-','')}.html" target="_blank">${f.cwe}</a></p>` : ''}
                        <p><strong>Description:</strong> ${f.description}</p>
                        ${f.offset !== undefined ? `<p><strong>Offset:</strong> 0x${f.offset.toString(16).toUpperCase()}</p>` : ''}
                        ${f.evidence ? `<p><strong>Evidence:</strong></p><pre>${f.evidence}</pre>` : ''}
                    </div>`;
                });
                
                html += `</body></html>`;
                
                const blob = new Blob([html], {type: 'text/html'});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security_report_${filename}.html`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }
        
        if (scanBtn) {
            scanBtn.addEventListener('click', async () => {
                if (!this.currentData || !this.currentFile) {
                    alert("No firmware loaded.");
                    return;
                }
                scanBtn.disabled = true;
                scanBtn.innerText = "Scanning... (This may take a moment)";
                this.updateProgress('Scanning firmware for secrets...', 50);
                
                try {
                    // Use native File stream from disk
                    const bodyData = this.currentFile || new Blob([this.currentData], { type: 'application/octet-stream' });
                    const res = await fetch('/api/scan-secrets', {
                        method: 'POST',
                        body: bodyData
                    });
                    
                    const data = await res.json();
                    if (!data.success) {
                        throw new Error(data.error || "Unknown backend error");
                    }
                    
                    // Merge new findings into existing security results
                    if (!this.securityResults) {
                        this.securityResults = { riskScore: 0, findings: [], stats: { total: 0 }, summary: { riskLevel: 'CLEAN' } };
                    }
                    
                    for (const f of data.findings) {
                        this.securityResults.findings.push({
                            severity: f.severity,
                            category: 'credential',
                            title: f.type,
                            description: f.description,
                            cwe: 'CWE-798',
                            offset: f.offset,
                            evidence: `Secret: ${f.secret}\nContext: ${f.context}`
                        });
                        // Calculate max CVSS score
                        const cvssMap = { critical: 9.8, high: 7.5, medium: 5.5, low: 2.5, info: 0.0 };
                        this.securityResults.riskScore = this.securityResults.riskScore || 0.0;
                        const vulnScore = cvssMap[f.severity] || 0.0;
                        if (vulnScore > this.securityResults.riskScore) {
                            this.securityResults.riskScore = vulnScore;
                        }
                    }
                    
                    this.securityResults.riskScore = parseFloat(this.securityResults.riskScore.toFixed(1));
                    
                    // Update stats
                    this.securityResults.stats = this.securityResults.stats || {};
                    this.securityResults.stats.total = this.securityResults.findings.length;
                    
                    // Update summary
                    if (this.securityResults.riskScore >= 9.0) this.securityResults.summary.riskLevel = 'CRITICAL';
                    else if (this.securityResults.riskScore >= 7.0) this.securityResults.summary.riskLevel = 'HIGH';
                    else if (this.securityResults.riskScore >= 4.0) this.securityResults.summary.riskLevel = 'MEDIUM';
                    else if (this.securityResults.riskScore >= 0.1) this.securityResults.summary.riskLevel = 'LOW';
                    
                    this.updateSecurity(this.securityResults);
                    this.renderFindings(this.securityResults.findings);
                    this.updateProgress('Secret scan complete', 100);
                } catch (e) {
                    alert("Error scanning for secrets: " + e.message);
                    this.updateProgress('Error', 0);
                } finally {
                    scanBtn.disabled = false;
                    scanBtn.innerText = "🔍 Deep Scan Secrets";
                }
            });
        }
    }

    updateSecurity(result) {
        // Update overview stat
        const statEl = document.getElementById('stat-security');
        if (statEl) statEl.innerText = result.stats.total;

        // Update risk gauge
        const score = result.riskScore || 0.0;
        const gaugeArc = document.getElementById('risk-gauge-arc');
        const scoreValue = document.getElementById('risk-score-value');
        const riskLevel = document.getElementById('risk-level');

        if (scoreValue) {
            // Display exactly 1 decimal place (e.g., 9.8 or 10.0)
            scoreValue.innerText = score.toFixed(1);
        }
        if (gaugeArc) {
            const circumference = 339.29;
            const offset = circumference - (score / 10.0) * circumference;
            gaugeArc.style.strokeDashoffset = offset;
            // Color based on CVSS score
            if (score >= 9.0) gaugeArc.style.stroke = '#ff3355'; // Critical
            else if (score >= 7.0) gaugeArc.style.stroke = '#ff8c00'; // High
            else if (score >= 4.0) gaugeArc.style.stroke = '#ffcc00'; // Medium
            else if (score >= 0.1) gaugeArc.style.stroke = '#3498db'; // Low
            else gaugeArc.style.stroke = '#00ff88'; // Clean
        }
        if (riskLevel && result.summary) {
            riskLevel.innerText = result.summary.riskLevel;
            riskLevel.className = 'risk-level ' + (result.summary.riskLevel || 'clean').toLowerCase();
        }

        // Update severity counts
        const sevIds = { critical: 'sev-critical-count', high: 'sev-high-count', medium: 'sev-medium-count', low: 'sev-low-count', info: 'sev-info-count' };
        for (const [sev, id] of Object.entries(sevIds)) {
            const el = document.getElementById(id);
            if (el) el.innerText = result.stats[sev] || 0;
        }

        // Render findings table
        this.renderFindings(result.findings);
    }

    renderFindings(allFindings) {
        const tbody = document.getElementById('findings-tbody');
        const countEl = document.getElementById('findings-count');
        if (!tbody) return;

        // Apply filters
        const sevFilter = document.getElementById('security-sev-filter');
        const catFilter = document.getElementById('security-cat-filter');
        const searchInput = document.getElementById('security-search');

        let findings = allFindings || [];
        if (sevFilter && sevFilter.value !== 'all') {
            findings = findings.filter(f => f.severity === sevFilter.value);
        }
        if (catFilter && catFilter.value !== 'all') {
            findings = findings.filter(f => f.category === catFilter.value);
        }
        if (searchInput && searchInput.value.trim()) {
            const q = searchInput.value.trim().toLowerCase();
            findings = findings.filter(f =>
                (f.name && f.name.toLowerCase().includes(q)) ||
                (f.description && f.description.toLowerCase().includes(q)) ||
                (f.evidence && f.evidence.toLowerCase().includes(q))
            );
        }

        if (countEl) countEl.innerText = findings.length;

        if (findings.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No findings match the current filters.</td></tr>';
            return;
        }

        const sevIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
        const catLabels = {
            credential: '🔑 Credential', private_key: '🗝️ Private Key', api_key: '🔐 API Key',
            token: '🎫 Token', secret: '🤫 Secret', backdoor: '🚪 Backdoor',
            vulnerable_function: '⚠️ Unsafe Func', weak_crypto: '🔓 Weak Crypto',
            insecure_protocol: '🌐 Insecure Proto', hardcoded_ip: '📡 Hardcoded IP',
            sensitive_path: '📁 Sensitive Path', default_credential: '👤 Default Cred',
            buffer_overflow: '💥 Buffer Overflow', command_injection: '💉 Cmd Injection',
            format_string: '📝 Format String', info_leak: 'ℹ️ Info Leak',
            sensitive_config: '⚙️ Config', certificate: '📜 Certificate', debug_info: '🐛 Debug',
            network: '🌐 Network'
        };

        let html = '';
        findings.forEach(f => {
            const sev = f.severity || 'info';
            const icon = sevIcons[sev] || '⚪';
            const catLabel = catLabels[f.category] || f.category;
            const cwe = f.cwe ? `<a href="https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-','')}.html" target="_blank" class="cwe-link">${f.cwe}</a>` : '—';
            const offset = f.offset !== undefined ? '0x' + f.offset.toString(16).toUpperCase().padStart(8, '0') : '—';
            const evidence = f.evidence ? this.escapeHtml(f.evidence) : '—';

            html += `<tr class="finding-row sev-${sev}">
                <td><span class="severity-badge sev-${sev}">${icon} ${sev.toUpperCase()}</span></td>
                <td><span class="category-badge">${catLabel}</span></td>
                <td class="finding-name">${this.escapeHtml(f.name || '')}</td>
                <td class="finding-desc">${this.escapeHtml(f.description || '')}</td>
                <td class="finding-cwe">${cwe}</td>
                <td class="mono">${offset}</td>
                <td class="finding-evidence mono" style="word-break: break-all; white-space: normal; max-width: 400px; max-height: 200px; overflow-y: auto; display: inline-block;">${evidence}</td>
            </tr>`;
        });
        tbody.innerHTML = html;
    }

    exportSecurityReport() {
        if (!this.securityResults) return;
        const r = this.securityResults;
        let report = `Firmware-X v1.0.0 Security Report\n`;
        report += `${'='.repeat(60)}\n`;
        report += `File: ${this.currentFile ? this.currentFile.name : 'Unknown'}\n`;
        report += `Date: ${new Date().toISOString()}\n`;
        report += `Risk Score: ${r.riskScore}/100 (${r.summary.riskLevel})\n`;
        report += `Total Findings: ${r.stats.total}\n`;
        report += `  Critical: ${r.stats.critical}  High: ${r.stats.high}  Medium: ${r.stats.medium}  Low: ${r.stats.low}  Info: ${r.stats.info}\n`;
        report += `${'='.repeat(60)}\n\n`;

        r.findings.forEach((f, i) => {
            report += `[${(i + 1).toString().padStart(3)}] ${f.severity.toUpperCase()} — ${f.name}\n`;
            report += `      Category: ${f.category}\n`;
            if (f.cwe) report += `      CWE: ${f.cwe}\n`;
            report += `      ${f.description}\n`;
            if (f.offset !== undefined) report += `      Offset: 0x${f.offset.toString(16)}\n`;
            if (f.evidence) report += `      Evidence: ${f.evidence}\n`;
            report += `\n`;
        });

        const blob = new Blob([report], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `firmware-x-v1.0.0-security-report-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Instantiate and expose globally for inline onclick handlers
const app = new FirmwareAnalyzer();
window.app = app;
