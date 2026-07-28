#!/usr/bin/env node
/**
 * FirmwareX CLI — Command-Line Firmware Analysis Tool
 * Cross-platform: Windows + Linux + macOS
 * 
 * Usage: node cli.js <command> <file> [options]
 */

const { Command } = require('commander');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ── Load Analysis Modules ─────────────────────────────────
const FileDetector = require('./modules/file-detector');
const BinaryParser = require('./modules/binary-parser');
const HexDecoder = require('./modules/hex-decoder');
const EntropyAnalyzer = require('./modules/entropy-analyzer');
const StringExtractor = require('./modules/string-extractor');
const HexViewer = require('./modules/hex-viewer');
const DecryptionEngine = require('./modules/decryption-engine');
const ArchiveExtractor = require('./modules/archive-extractor');
const LayerEngine = require('./modules/layer-engine');
const SecurityAnalyzer = require('./modules/security-analyzer');

// Load fflate and jszip for archive extraction
let fflate, JSZip;
try { fflate = require('fflate'); } catch(e) { /* optional */ }
try { JSZip = require('jszip'); } catch(e) { /* optional */ }

// ── ASCII Banner ──────────────────────────────────────────
const banner = `
${chalk.cyan('╔═══════════════════════════════════════════════════╗')}
${chalk.cyan('║')}  ${chalk.bold.hex('#00d4ff')('F')}${chalk.bold.hex('#3ba8f7')('i')}${chalk.bold.hex('#7b2ff7')('r')}${chalk.bold.hex('#a62dc6')('m')}${chalk.bold.hex('#d12b96')('w')}${chalk.bold.hex('#ff2d95')('a')}${chalk.bold.hex('#ff5c7a')('r')}${chalk.bold.hex('#ff8c00')('e')}${chalk.bold.hex('#00d4ff')('X')} ${chalk.gray('— Firmware Analysis CLI v1.0.0')}    ${chalk.cyan('║')}
${chalk.cyan('║')}  ${chalk.gray('All processing runs 100% locally on your machine')} ${chalk.cyan('║')}
${chalk.cyan('╚═══════════════════════════════════════════════════╝')}
`;

// ── Utility Functions ─────────────────────────────────────
function loadFile(filePath) {
    if (!fs.existsSync(filePath)) {
        console.error(chalk.red(`\n  ✖ File not found: ${filePath}`));
        process.exit(1);
    }
    const buffer = fs.readFileSync(filePath);
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function computeHash(data) {
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
    return hash.digest('hex');
}

function printFileInfo(filePath, data) {
    const stat = fs.statSync(filePath);
    console.log(chalk.gray('\n  ─── File Information ───────────────────────────'));
    console.log(`  ${chalk.cyan('File:')}       ${chalk.white(path.basename(filePath))}`);
    console.log(`  ${chalk.cyan('Path:')}       ${chalk.gray(path.resolve(filePath))}`);
    console.log(`  ${chalk.cyan('Size:')}       ${chalk.yellow(formatSize(data.length))} (${data.length.toLocaleString()} bytes)`);
    console.log(`  ${chalk.cyan('SHA-256:')}    ${chalk.gray(computeHash(data))}`);
    console.log(`  ${chalk.cyan('Modified:')}   ${chalk.gray(stat.mtime.toISOString())}`);
}

function printSectionHeader(title) {
    console.log(chalk.gray(`\n  ─── ${title} ${'─'.repeat(Math.max(0, 45 - title.length))}`));
}

// ── Architecture Mapping ──────────────────────────────────
const ARCH_MAP = {
    'x86':       { arch: 'x86',       desc: 'Intel/AMD x86' },
    'arm':       { arch: 'arm',       desc: 'ARM 32-bit' },
    'arm64':     { arch: 'arm64',     desc: 'ARM 64-bit (AArch64)' },
    'mips':      { arch: 'mips',      desc: 'MIPS' },
    'ppc':       { arch: 'ppc',       desc: 'PowerPC' },
    'sparc':     { arch: 'sparc',     desc: 'SPARC' },
    'sysz':      { arch: 'sysz',      desc: 'IBM SystemZ (s390x)' },
    'm68k':      { arch: 'm68k',      desc: 'Motorola 68000' },
    'xcore':     { arch: 'xcore',     desc: 'XMOS XCore' },
    'tms320c6x': { arch: 'tms320c6x', desc: 'TI TMS320C6x DSP' },
    'm680x':     { arch: 'm680x',     desc: 'Motorola/Freescale M680x' },
    'evm':       { arch: 'evm',       desc: 'Ethereum Virtual Machine' }
};

// ── Program Setup ─────────────────────────────────────────
const program = new Command();

program
    .name('firmwarex')
    .description('FirmwareX — Cross-platform firmware decompilation & analysis tool')
    .version('1.0.0')
    .option('--wsl', 'Force execution through Windows Subsystem for Linux (WSL) for native commands')
    .addHelpText('before', banner);

// Helper to format command execution for the OS
function buildCommand(baseCmd, args) {
    const isWin = process.platform === 'win32';
    const forceWsl = program.opts().wsl;
    if (isWin && forceWsl) {
        return `wsl ${baseCmd} ${args}`;
    } else if (isWin && baseCmd === 'objdump') {
        return `objdump.exe ${args}`;
    }
    return `${baseCmd} ${args}`;
}

// ── Command: detect ───────────────────────────────────────
program
    .command('detect <file>')
    .description('Detect file type(s) using magic byte signatures')
    .option('-s, --scan', 'Scan entire file for all embedded signatures')
    .option('-j, --json', 'Output results as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const detector = new FileDetector();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        // Primary detection
        const result = detector.detect(data);
        
        if (opts.json) {
            const output = { primary: result };
            if (opts.scan) {
                output.embedded = detector.scanAll(data);
            }
            console.log(JSON.stringify(output, null, 2));
            return;
        }

        printSectionHeader('Primary Detection');
        if (result && result.type !== 'unknown') {
            console.log(`  ${chalk.green('✔')} ${chalk.bold(result.name || result.type)}`);
            console.log(`    ${chalk.gray('Type:')}        ${chalk.cyan(result.type)}`);
            if (result.description) console.log(`    ${chalk.gray('Description:')} ${result.description}`);
            if (result.confidence) console.log(`    ${chalk.gray('Confidence:')}  ${chalk.yellow(Math.round(result.confidence * 100) + '%')}`);
        } else {
            console.log(`  ${chalk.yellow('?')} ${chalk.gray('Unknown file type')}`);
        }

        // Embedded signature scan
        if (opts.scan) {
            const embedded = detector.scanAll(data);
            printSectionHeader('Embedded Signatures');
            if (embedded && embedded.length > 0) {
                console.log(`  ${chalk.green('Found')} ${chalk.bold(embedded.length)} ${chalk.green('signature(s):')}\n`);
                embedded.forEach((sig, i) => {
                    console.log(`  ${chalk.gray(`${i + 1}.`)} ${chalk.bold(sig.name || sig.type)} ${chalk.gray('at offset')} ${chalk.cyan('0x' + (sig.offset || 0).toString(16).toUpperCase())}`);
                    if (sig.description) console.log(`     ${chalk.gray(sig.description)}`);
                });
            } else {
                console.log(`  ${chalk.gray('No additional embedded signatures found')}`);
            }
        }
        console.log();
    });

// ── Command: analyze ──────────────────────────────────────
program
    .command('analyze <file>')
    .description('Full layer-by-layer firmware analysis')
    .option('-d, --depth <n>', 'Maximum recursion depth', parseInt, 10)
    .option('-o, --output <dir>', 'Save extracted layers to directory')
    .option('-j, --json', 'Output results as JSON')
    .action(async (file, opts) => {
        const data = loadFile(file);

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        const detector = new FileDetector();
        const extractor = new ArchiveExtractor(fflate, JSZip);
        const hexDecoder = new HexDecoder();
        const parser = new BinaryParser();
        const entropy = new EntropyAnalyzer();
        const strExtractor = new StringExtractor();

        // File detection
        const detection = detector.detect(data);
        const embedded = detector.scanAll(data);

        if (!opts.json) {
            printSectionHeader('File Type');
            console.log(`  ${chalk.green('✔')} ${chalk.bold(detection.name || detection.type || 'Unknown')}`);

            printSectionHeader('Embedded Signatures');
            if (embedded && embedded.length > 0) {
                embedded.forEach((sig, i) => {
                    console.log(`  ${chalk.gray(`${i + 1}.`)} ${chalk.bold(sig.name || sig.type)} ${chalk.gray('@')} ${chalk.cyan('0x' + (sig.offset || 0).toString(16))}`);
                });
            } else {
                console.log(`  ${chalk.gray('None found')}`);
            }
        }

        // Entropy
        const entropyResult = entropy.analyze(data, 256);
        if (!opts.json) {
            printSectionHeader('Entropy Analysis');
            console.log(`  ${chalk.cyan('Overall Entropy:')} ${chalk.yellow(entropyResult.overall.toFixed(4))} ${chalk.gray('bits/byte')}`);
            const classification = entropyResult.overall < 1 ? 'Empty/Padding' :
                entropyResult.overall < 4 ? 'Structured Data' :
                entropyResult.overall < 6 ? 'Executable Code' :
                entropyResult.overall < 7.5 ? 'Compressed' : 'Encrypted/Random';
            console.log(`  ${chalk.cyan('Classification:')}  ${chalk.yellow(classification)}`);

            // ASCII mini entropy bar
            const barWidth = 50;
            const filledWidth = Math.round((entropyResult.overall / 8) * barWidth);
            const bar = chalk.cyan('█'.repeat(filledWidth)) + chalk.gray('░'.repeat(barWidth - filledWidth));
            console.log(`  ${chalk.cyan('Entropy Bar:')}     [${bar}] ${(entropyResult.overall / 8 * 100).toFixed(1)}%`);
        }

        // Strings
        const strings = strExtractor.extract(data, { minLength: 4 });
        if (!opts.json) {
            printSectionHeader('String Extraction');
            console.log(`  ${chalk.cyan('Total Strings:')} ${chalk.yellow(strings.length)}`);
            if (strings.length > 0) {
                const stats = strExtractor.getStats ? strExtractor.getStats(strings) : {};
                if (stats.byType) {
                    Object.entries(stats.byType).forEach(([type, count]) => {
                        if (count > 0) {
                            const color = type === 'url' ? chalk.blue : type === 'credential' ? chalk.red : 
                                          type === 'crypto' ? chalk.magenta : type === 'path' ? chalk.green : chalk.gray;
                            console.log(`    ${color('●')} ${type}: ${chalk.yellow(count)}`);
                        }
                    });
                }
                console.log(`\n  ${chalk.gray('First 10 strings:')}`);
                strings.slice(0, 10).forEach(s => {
                    const str = typeof s === 'string' ? s : (s.string || s);
                    const offset = typeof s === 'object' && s.offset !== undefined ? chalk.cyan('0x' + s.offset.toString(16).padStart(8, '0')) + ' ' : '';
                    console.log(`    ${offset}${chalk.white(str.substring(0, 80))}${str.length > 80 ? chalk.gray('...') : ''}`);
                });
            }
        }

        // Binary parsing (if ELF or PE)
        if (detection.type === 'elf' || detection.type === 'pe') {
            if (!opts.json) printSectionHeader('Binary Structure');
            try {
                if (detection.type === 'elf') {
                    const elf = parser.parseELF(data);
                    if (!opts.json && elf) {
                        console.log(`  ${chalk.cyan('Format:')}     ELF ${elf.header.class === 2 ? '64-bit' : '32-bit'}`);
                        console.log(`  ${chalk.cyan('Machine:')}    ${elf.header.machineStr || 'Unknown'}`);
                        console.log(`  ${chalk.cyan('Endian:')}     ${elf.header.endianness === 1 ? 'Little' : 'Big'}`);
                        console.log(`  ${chalk.cyan('Entry:')}      ${chalk.yellow('0x' + (elf.header.entryPoint || 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('Sections:')}   ${(elf.sectionHeaders || []).length}`);
                        console.log(`  ${chalk.cyan('Segments:')}   ${(elf.programHeaders || []).length}`);
                    }
                } else if (detection.type === 'pe') {
                    const pe = parser.parsePE(data);
                    if (!opts.json && pe) {
                        console.log(`  ${chalk.cyan('Format:')}     PE ${pe.optionalHeader && pe.optionalHeader.magic === 0x20b ? '64-bit (PE32+)' : '32-bit (PE32)'}`);
                        console.log(`  ${chalk.cyan('Machine:')}    ${pe.fileHeader ? (pe.fileHeader.machineStr || 'Unknown') : 'Unknown'}`);
                        console.log(`  ${chalk.cyan('Entry:')}      ${chalk.yellow('0x' + (pe.optionalHeader ? pe.optionalHeader.entryPoint || 0 : 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('Sections:')}   ${(pe.sections || []).length}`);
                    }
                }
            } catch (e) {
                if (!opts.json) console.log(`  ${chalk.yellow('⚠')} Could not fully parse binary: ${e.message}`);
            }
        }

        // Layer extraction
        if (!opts.json) printSectionHeader('Layer Extraction');
        try {
            const engine = new LayerEngine(detector, extractor, hexDecoder, { maxDepth: opts.depth || 10 });
            const tree = await engine.analyze(data, path.basename(file));
            const stats = engine.getStats();
            
            if (!opts.json) {
                console.log(`  ${chalk.cyan('Total Layers:')} ${chalk.yellow(stats.totalLayers || 1)}`);
                console.log(`  ${chalk.cyan('Max Depth:')}    ${chalk.yellow(stats.maxDepthReached || 0)}`);
                if (stats.types) {
                    console.log(`  ${chalk.cyan('Types Found:')}`);
                    Object.entries(stats.types).forEach(([type, count]) => {
                        console.log(`    ${chalk.gray('●')} ${type}: ${chalk.yellow(count)}`);
                    });
                }

                // Save extracted layers
                if (opts.output && tree && tree.children && tree.children.length > 0) {
                    const outputDir = path.resolve(opts.output);
                    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
                    
                    function saveLayer(layer, dir) {
                        if (layer.data && layer.name) {
                            const filePath = path.join(dir, layer.name.replace(/[<>:"|?*]/g, '_'));
                            fs.writeFileSync(filePath, Buffer.from(layer.data));
                            console.log(`  ${chalk.green('✔')} Saved: ${chalk.gray(filePath)}`);
                        }
                        if (layer.children) {
                            layer.children.forEach(child => saveLayer(child, dir));
                        }
                    }
                    saveLayer(tree, outputDir);
                }
            }
        } catch (e) {
            if (!opts.json) console.log(`  ${chalk.yellow('⚠')} Layer extraction: ${e.message}`);
        }

        if (opts.json) {
            console.log(JSON.stringify({
                file: path.basename(file),
                size: data.length,
                sha256: computeHash(data),
                detection,
                embedded,
                entropy: { overall: entropyResult.overall, blocks: entropyResult.blocks ? entropyResult.blocks.length : 0 },
                strings: { count: strings.length, first10: strings.slice(0, 10) }
            }, null, 2));
        }

        console.log();
    });

// ── Command: entropy ──────────────────────────────────────
program
    .command('entropy <file>')
    .description('Entropy analysis with visual graph')
    .option('-b, --block-size <n>', 'Block size in bytes', parseInt, 256)
    .option('-w, --width <n>', 'ASCII chart width', parseInt, 60)
    .option('-j, --json', 'Output as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const analyzer = new EntropyAnalyzer();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        const result = analyzer.analyze(data, opts.blockSize);

        if (opts.json) {
            console.log(JSON.stringify(result, null, 2));
            return;
        }

        printSectionHeader('Entropy Analysis');
        console.log(`  ${chalk.cyan('Overall Entropy:')} ${chalk.yellow(result.overall.toFixed(6))} ${chalk.gray('bits/byte (max 8.0)')}`);
        console.log(`  ${chalk.cyan('Block Size:')}      ${chalk.yellow(opts.blockSize)} bytes`);
        console.log(`  ${chalk.cyan('Total Blocks:')}    ${chalk.yellow(result.blocks ? result.blocks.length : 0)}`);

        // Classification
        const cl = result.overall < 1 ? chalk.blue('Empty/Padding') :
            result.overall < 4 ? chalk.green('Structured/Text') :
            result.overall < 6 ? chalk.yellow('Executable Code') :
            result.overall < 7.5 ? chalk.hex('#ff8c00')('Compressed') : chalk.red('Encrypted/Random');
        console.log(`  ${chalk.cyan('Classification:')}  ${cl}`);

        // Regions
        if (result.regions && result.regions.length > 0) {
            printSectionHeader('Detected Regions');
            result.regions.forEach((region, i) => {
                const color = region.type === 'encrypted' ? chalk.red :
                    region.type === 'compressed' ? chalk.hex('#ff8c00') :
                    region.type === 'code' ? chalk.yellow :
                    region.type === 'text' ? chalk.green : chalk.blue;
                console.log(`  ${chalk.gray(`${i + 1}.`)} ${color(region.type.padEnd(12))} ${chalk.cyan('0x' + region.start.toString(16).padStart(8, '0'))} → ${chalk.cyan('0x' + region.end.toString(16).padStart(8, '0'))} ${chalk.gray('avg:')} ${chalk.yellow(region.avgEntropy.toFixed(2))}`);
            });
        }

        // ASCII entropy graph
        if (result.blocks && result.blocks.length > 0) {
            printSectionHeader('Entropy Graph');
            console.log(`  ${chalk.gray('0.0')}${'─'.repeat(opts.width - 6)}${chalk.gray('8.0')}`);
            
            // Downsample to fit terminal
            const maxRows = 30;
            const step = Math.max(1, Math.floor(result.blocks.length / maxRows));
            
            for (let i = 0; i < result.blocks.length && i / step < maxRows; i += step) {
                const block = result.blocks[i];
                const entropy = block.entropy || block;
                const barLen = Math.round((entropy / 8) * (opts.width - 8));
                const offset = '0x' + ((block.offset || i * opts.blockSize)).toString(16).padStart(6, '0');
                
                let bar;
                if (entropy < 3.5) bar = chalk.blue('█'.repeat(barLen));
                else if (entropy < 5.0) bar = chalk.green('█'.repeat(barLen));
                else if (entropy < 6.5) bar = chalk.yellow('█'.repeat(barLen));
                else if (entropy < 7.5) bar = chalk.hex('#ff8c00')('█'.repeat(barLen));
                else bar = chalk.red('█'.repeat(barLen));

                console.log(`  ${chalk.gray(offset)} ${bar}`);
            }
            
            console.log();
            console.log(`  ${chalk.gray('Legend:')} ${chalk.blue('■')} Empty/Text  ${chalk.green('■')} Structured  ${chalk.yellow('■')} Code  ${chalk.hex('#ff8c00')('■')} Compressed  ${chalk.red('■')} Encrypted`);
        }
        console.log();
    });

// ── Command: strings ──────────────────────────────────────
program
    .command('strings <file>')
    .description('Extract readable strings from binary')
    .option('-m, --min-length <n>', 'Minimum string length', parseInt, 4)
    .option('-e, --encoding <enc>', 'Encoding: ascii, utf8, utf16', 'ascii')
    .option('-t, --type <type>', 'Filter by type: url, path, credential, crypto, all', 'all')
    .option('-n, --max <n>', 'Maximum number of strings to show', parseInt, 0)
    .option('-j, --json', 'Output as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const extractor = new StringExtractor();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        let results;
        if (extractor.extractWithPatterns) {
            results = extractor.extractWithPatterns(data, { minLength: opts.minLength, encoding: opts.encoding });
        } else {
            results = extractor.extract(data, { minLength: opts.minLength, encoding: opts.encoding });
        }

        // Filter by type
        if (opts.type !== 'all' && results.length > 0 && typeof results[0] === 'object') {
            results = results.filter(r => r.type === opts.type);
        }

        // Limit
        if (opts.max > 0) {
            results = results.slice(0, opts.max);
        }

        if (opts.json) {
            console.log(JSON.stringify(results, null, 2));
            return;
        }

        printSectionHeader(`Strings (min length: ${opts.minLength})`);
        console.log(`  ${chalk.cyan('Total Found:')} ${chalk.yellow(results.length)}`);

        if (extractor.getStats) {
            const stats = extractor.getStats(results);
            if (stats.byType) {
                Object.entries(stats.byType).forEach(([type, count]) => {
                    if (count > 0) {
                        const color = type === 'url' ? chalk.blue : type === 'credential' ? chalk.red :
                            type === 'crypto' ? chalk.magenta : type === 'path' ? chalk.green :
                            type === 'ip' ? chalk.yellow : type === 'email' ? chalk.hex('#ff8c00') : chalk.gray;
                        console.log(`    ${color('●')} ${type}: ${count}`);
                    }
                });
            }
        }

        console.log();
        results.forEach((item, i) => {
            const str = typeof item === 'string' ? item : (item.string || item);
            const offset = typeof item === 'object' && item.offset !== undefined ?
                chalk.cyan('0x' + item.offset.toString(16).padStart(8, '0')) : chalk.gray('        ');
            const type = typeof item === 'object' && item.type ?
                (item.type === 'url' ? chalk.blue(`[${item.type}]`) :
                 item.type === 'credential' ? chalk.red(`[${item.type}]`) :
                 item.type === 'crypto' ? chalk.magenta(`[${item.type}]`) :
                 item.type === 'path' ? chalk.green(`[${item.type}]`) :
                 chalk.gray(`[${item.type}]`)) : '';

            console.log(`  ${offset} ${type.padEnd(20)} ${chalk.white(str.substring(0, 100))}${str.length > 100 ? chalk.gray('...') : ''}`);
        });
        console.log();
    });

// ── Command: hexdump ──────────────────────────────────────
program
    .command('hexdump <file>')
    .description('Hex dump of file contents')
    .option('-o, --offset <hex>', 'Start offset (hex)', '0')
    .option('-l, --length <n>', 'Number of bytes to show', parseInt, 256)
    .option('-w, --width <n>', 'Bytes per row (16 or 32)', parseInt, 16)
    .option('--no-ascii', 'Hide ASCII column')
    .action((file, opts) => {
        const data = loadFile(file);
        const viewer = new HexViewer(null);
        viewer.setData(data);

        console.log(banner);
        printFileInfo(file, data);
        printSectionHeader('Hex Dump');

        const startOffset = parseInt(opts.offset, 16) || 0;
        const length = Math.min(opts.length, data.length - startOffset);
        const bytesPerRow = opts.width === 32 ? 32 : 16;

        // Print header
        let header = chalk.gray('  Offset    ');
        for (let i = 0; i < bytesPerRow; i++) {
            header += chalk.gray(i.toString(16).toUpperCase().padStart(2, '0') + ' ');
            if (i === 7 && bytesPerRow === 16) header += ' ';
        }
        if (opts.ascii !== false) header += chalk.gray(' ASCII');
        console.log(header);
        console.log(chalk.gray('  ' + '─'.repeat(bytesPerRow * 3 + 14 + (opts.ascii !== false ? 18 : 0))));

        // Print rows
        for (let offset = startOffset; offset < startOffset + length; offset += bytesPerRow) {
            const rowBytes = data.slice(offset, Math.min(offset + bytesPerRow, data.length));
            
            let hex = '';
            let ascii = '';
            for (let i = 0; i < bytesPerRow; i++) {
                if (i < rowBytes.length) {
                    const byte = rowBytes[i];
                    if (byte === 0x00) {
                        hex += chalk.gray('00 ');
                    } else if (byte >= 0x20 && byte <= 0x7e) {
                        hex += chalk.white(byte.toString(16).toUpperCase().padStart(2, '0') + ' ');
                    } else {
                        hex += chalk.yellow(byte.toString(16).toUpperCase().padStart(2, '0') + ' ');
                    }
                    ascii += (byte >= 0x20 && byte <= 0x7e) ? chalk.green(String.fromCharCode(byte)) : chalk.gray('.');
                } else {
                    hex += '   ';
                    ascii += ' ';
                }
                if (i === 7 && bytesPerRow === 16) hex += ' ';
            }

            const offsetStr = chalk.cyan('0x' + offset.toString(16).toUpperCase().padStart(8, '0'));
            let line = `  ${offsetStr}  ${hex}`;
            if (opts.ascii !== false) line += ` ${chalk.gray('│')}${ascii}${chalk.gray('│')}`;
            console.log(line);
        }
        console.log();
    });

// ── Command: decrypt ──────────────────────────────────────
program
    .command('decrypt <file>')
    .description('Decrypt firmware with specified method and key')
    .option('-m, --method <method>', 'Decryption method: xor, aes, rc4, rot, caesar', 'xor')
    .option('-k, --key <key>', 'Decryption key')
    .option('-f, --key-format <fmt>', 'Key format: hex, ascii, base64', 'hex')
    .option('--iv <iv>', 'Initialization vector (hex) for AES')
    .option('--mode <mode>', 'AES mode: cbc, ecb, ctr, gcm', 'cbc')
    .option('--key-size <size>', 'AES key size: 128, 192, 256', parseInt, 128)
    .option('-b, --brute-force', 'XOR single-byte brute-force')
    .option('-n, --shift <n>', 'ROT/Caesar shift value', parseInt, 13)
    .option('-o, --output <file>', 'Save decrypted output to file')
    .option('-j, --json', 'Output as JSON')
    .action(async (file, opts) => {
        const data = loadFile(file);
        const engine = new DecryptionEngine();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        let result;

        if (opts.bruteForce) {
            // XOR brute-force
            if (!opts.json) printSectionHeader('XOR Brute-Force');
            const results = engine.xorBruteForce(data, { sampleSize: 1024, topN: 10 });
            
            if (opts.json) {
                console.log(JSON.stringify(results, null, 2));
                return;
            }

            console.log(`  ${chalk.cyan('Testing all 256 single-byte XOR keys...')}\n`);
            if (results && results.length > 0) {
                results.forEach((r, i) => {
                    const keyHex = '0x' + (r.key || 0).toString(16).toUpperCase().padStart(2, '0');
                    const score = ((r.score || 0) * 100).toFixed(1);
                    const preview = r.preview || '';
                    console.log(`  ${chalk.gray(`${(i + 1).toString().padStart(2)}.`)} Key: ${chalk.cyan(keyHex)}  Score: ${chalk.yellow(score + '%')}  Preview: ${chalk.gray(preview.substring(0, 60))}`);
                });
            }
            console.log();
            return;
        }

        // Parse key
        let keyBytes;
        if (opts.key) {
            try {
                keyBytes = engine.parseKey(opts.key, opts.keyFormat);
            } catch (e) {
                console.error(chalk.red(`\n  ✖ Invalid key: ${e.message}`));
                process.exit(1);
            }
        }

        if (!opts.json) printSectionHeader(`Decryption (${opts.method.toUpperCase()})`);

        try {
            switch (opts.method.toLowerCase()) {
                case 'xor':
                    if (!keyBytes) { console.error(chalk.red('  ✖ Key required for XOR decryption')); process.exit(1); }
                    result = engine.xorDecrypt(data, keyBytes.length === 1 ? keyBytes[0] : keyBytes);
                    break;
                case 'aes':
                    if (!keyBytes) { console.error(chalk.red('  ✖ Key required for AES decryption')); process.exit(1); }
                    let ivBytes = null;
                    if (opts.iv) ivBytes = engine.parseKey(opts.iv, 'hex');
                    const aesResult = await engine.aesDecrypt(data, keyBytes, ivBytes, opts.mode.toUpperCase(), opts.keySize);
                    if (aesResult.success) {
                        result = aesResult.data;
                    } else {
                        console.error(chalk.red(`  ✖ AES decryption failed: ${aesResult.error}`));
                        process.exit(1);
                    }
                    break;
                case 'rc4':
                    if (!keyBytes) { console.error(chalk.red('  ✖ Key required for RC4 decryption')); process.exit(1); }
                    result = engine.rc4Decrypt(data, keyBytes);
                    break;
                case 'rot':
                case 'rot13':
                    const text = Buffer.from(data).toString('ascii');
                    const rotResult = opts.shift !== 13 ? engine.rotN(text, opts.shift) : engine.rot13(text);
                    result = new Uint8Array(Buffer.from(rotResult));
                    break;
                case 'caesar':
                    if (!opts.json) {
                        const caesarText = Buffer.from(data.slice(0, 1000)).toString('ascii');
                        const caesarResults = engine.caesarBruteForce(caesarText);
                        caesarResults.forEach((r, i) => {
                            console.log(`  ${chalk.gray(`${(i + 1).toString().padStart(2)}.`)} Shift: ${chalk.cyan(r.shift.toString().padStart(2))}  Score: ${chalk.yellow(r.score.toFixed(1).padStart(6))}  ${chalk.gray(r.text.substring(0, 60))}`);
                        });
                        console.log();
                        return;
                    }
                    break;
                default:
                    console.error(chalk.red(`  ✖ Unknown method: ${opts.method}`));
                    process.exit(1);
            }
        } catch (e) {
            console.error(chalk.red(`  ✖ Decryption error: ${e.message}`));
            process.exit(1);
        }

        if (result) {
            if (!opts.json) console.log(`  ${chalk.green('✔')} Decryption successful (${formatSize(result.length)})`);

            // Save output
            if (opts.output) {
                fs.writeFileSync(opts.output, Buffer.from(result));
                if (!opts.json) console.log(`  ${chalk.green('✔')} Saved to: ${chalk.gray(path.resolve(opts.output))}`);
            } else if (!opts.json) {
                // Show preview hex dump
                console.log(`\n  ${chalk.gray('Preview (first 128 bytes):')}`);
                for (let offset = 0; offset < Math.min(128, result.length); offset += 16) {
                    const rowBytes = result.slice(offset, Math.min(offset + 16, result.length));
                    let hex = '';
                    let ascii = '';
                    for (let i = 0; i < 16; i++) {
                        if (i < rowBytes.length) {
                            hex += rowBytes[i].toString(16).toUpperCase().padStart(2, '0') + ' ';
                            ascii += (rowBytes[i] >= 0x20 && rowBytes[i] <= 0x7e) ? String.fromCharCode(rowBytes[i]) : '.';
                        }
                    }
                    console.log(`  ${chalk.cyan('0x' + offset.toString(16).padStart(8, '0'))}  ${chalk.white(hex.padEnd(48))} ${chalk.gray(ascii)}`);
                }
            }
        }
        console.log();
    });

// ── Command: disasm ───────────────────────────────────────
program
    .command('disasm <file>')
    .description('Disassemble binary code')
    .option('-a, --arch <arch>', `Architecture: ${Object.keys(ARCH_MAP).join(', ')}`, 'x86')
    .option('-m, --mode <mode>', 'Mode: 16, 32, 64, thumb, arm, micro, mips32, mips64, v8, v9', '32')
    .option('-e, --endian <endian>', 'Endianness: little, big, auto', 'auto')
    .option('-o, --offset <hex>', 'Start offset in file (hex)', '0')
    .option('-l, --length <n>', 'Number of bytes to disassemble', parseInt, 0)
    .option('-b, --base-address <hex>', 'Base address for disassembly', '0')
    .option('-n, --max-instructions <n>', 'Maximum instructions to disassemble', parseInt, 100)
    .option('--auto', 'Auto-detect architecture from ELF/PE headers')
    .option('-j, --json', 'Output as JSON')
    .action((file, opts) => {
        const data = loadFile(file);

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
            printSectionHeader('Disassembly');
        }

        // Auto-detect architecture
        let arch = opts.arch;
        let mode = opts.mode;
        let endian = opts.endian;

        if (opts.auto) {
            const parser = new BinaryParser();
            try {
                const archInfo = parser.getArchitectureInfo(data);
                if (archInfo) {
                    arch = archInfo.arch || arch;
                    mode = archInfo.mode || mode;
                    endian = archInfo.endian || endian;
                    if (!opts.json) {
                        console.log(`  ${chalk.green('✔')} Auto-detected: ${chalk.cyan(arch)} ${chalk.yellow(mode)} ${chalk.gray(endian + '-endian')}`);
                    }
                }
            } catch (e) {
                if (!opts.json) console.log(`  ${chalk.yellow('⚠')} Auto-detect failed: ${e.message}. Using specified arch.`);
            }
        }

        if (!opts.json) {
            console.log(`  ${chalk.cyan('Architecture:')} ${chalk.yellow(arch)} (${ARCH_MAP[arch] ? ARCH_MAP[arch].desc : arch})`);
            console.log(`  ${chalk.cyan('Mode:')}         ${chalk.yellow(mode)}`);
            console.log(`  ${chalk.cyan('Endianness:')}   ${chalk.yellow(endian)}`);
            console.log();
            console.log(`  ${chalk.red('⚠ Note:')} Capstone.js WASM disassembly requires the web UI.`);
            console.log(`  ${chalk.gray('  For CLI disassembly, install native objdump/capstone:')}`);
            console.log(`  ${chalk.gray('  Ubuntu/Kali:')} ${chalk.cyan('sudo apt install binutils')}`);
            console.log(`  ${chalk.gray('  Then use:')} ${chalk.cyan(`objdump -d -m ${arch} ${file}`)}`);
        }

        // Try native objdump if available
        try {
            const { execSync } = require('child_process');
            const offset = parseInt(opts.offset, 16) || 0;
            const baseAddr = parseInt(opts.baseAddress, 16) || 0;

            // Check if it's an ELF/PE and objdump is available
            const detector = new FileDetector();
            const detection = detector.detect(data);

            if (detection.type === 'elf' || detection.type === 'pe') {
                try {
                    const cmdStr = buildCommand('objdump', `-d --no-show-raw-insn -M intel "${file}"`);
                    const result = execSync(`${cmdStr} 2>&1`, { maxBuffer: 10 * 1024 * 1024, timeout: 30000 }).toString();

                    if (!opts.json) {
                        const lines = result.split('\n').slice(0, opts.maxInstructions + 10);
                        lines.forEach(line => {
                            if (line.match(/^\s*[0-9a-f]+:/i)) {
                                const parts = line.match(/^\s*([0-9a-f]+):\s*(.*)/i);
                                if (parts) {
                                    console.log(`  ${chalk.cyan(parts[1].padStart(8, '0'))}:  ${chalk.white(parts[2])}`);
                                }
                            } else if (line.match(/^[0-9a-f]+ </i)) {
                                console.log(`\n  ${chalk.yellow(line)}`);
                            }
                        });
                    } else {
                        console.log(JSON.stringify({ output: result.split('\n').slice(0, opts.maxInstructions) }, null, 2));
                    }
                    console.log();
                    return;
                } catch (e) {
                    // objdump not available, fall through
                }
            }
        } catch (e) {
            // Native tools not available
        }

        if (!opts.json) {
            console.log(`\n  ${chalk.yellow('ℹ')} For full disassembly, use the ${chalk.cyan('Web UI')}: ${chalk.cyan('npm start')}`);
        }
        console.log();
    });

// ── Command: extract ──────────────────────────────────────
program
    .command('extract <file>')
    .description('Extract all layers from firmware to a directory')
    .option('-o, --output <dir>', 'Output directory', './extracted')
    .option('-d, --depth <n>', 'Maximum recursion depth', parseInt, 10)
    .option('--backend <engine>', 'Extraction backend (js, binwalk)', 'js')
    .action(async (file, opts) => {
        const data = loadFile(file);

        console.log(banner);
        printFileInfo(file, data);
        printSectionHeader('Extracting Layers');
        
        const outputDir = path.resolve(opts.output);
        if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

        if (opts.backend === 'binwalk') {
            console.log(`  ${chalk.cyan('Backend:')}  Native CLI (binwalk / unsquashfs)`);
            try {
                const { execSync } = require('child_process');
                // Use the cross-platform wrapper for WSL support
                const binwalkCmd = buildCommand('binwalk', `-Me "${file}" -C "${outputDir}"`);
                console.log(`  ${chalk.gray('Executing:')} ${binwalkCmd}`);
                execSync(binwalkCmd, { stdio: 'inherit' });
                console.log(`\n  ${chalk.green('✔')} Extraction complete via binwalk.`);
            } catch (e) {
                console.error(`\n  ${chalk.red('✖')} Binwalk extraction failed. Try using the --wsl flag if you are on Windows, or use the default JS backend.`);
            }
            return;
        }

        console.log(`  ${chalk.cyan('Backend:')}  Pure JS Engine`);
        const detector = new FileDetector();
        const extractor = new ArchiveExtractor(fflate, JSZip);
        const hexDecoder = new HexDecoder();
        const engine = new LayerEngine(detector, extractor, hexDecoder, { maxDepth: opts.depth });

        try {
            const tree = await engine.analyze(data, path.basename(file));

            let savedCount = 0;
            function saveLayer(layer, dir, depth) {
                const indent = '  '.repeat(depth + 1);
                if (layer.data && layer.name) {
                    const safeName = (layer.name || 'layer_' + savedCount).replace(/[<>:"|?*]/g, '_');
                    const destDir = opts.flat ? outputDir : dir;
                    const filePath = path.join(destDir, safeName);
                    
                    if (!fs.existsSync(path.dirname(filePath))) {
                        fs.mkdirSync(path.dirname(filePath), { recursive: true });
                    }
                    fs.writeFileSync(filePath, Buffer.from(layer.data));
                    console.log(`${indent}${chalk.green('✔')} ${chalk.white(safeName)} ${chalk.gray('(' + formatSize(layer.data.length) + ')')}`);
                    savedCount++;
                }
                if (layer.children) {
                    const childDir = layer.name ? path.join(dir, layer.name.replace(/[<>:"|?*]/g, '_') + '_contents') : dir;
                    layer.children.forEach(child => saveLayer(child, childDir, depth + 1));
                }
            }

            saveLayer(tree, outputDir, 0);
            console.log(`\n  ${chalk.green('✔')} Extracted ${chalk.yellow(savedCount)} layer(s) to ${chalk.cyan(outputDir)}`);
        } catch (e) {
            console.error(`  ${chalk.red('✖')} Extraction failed: ${e.message}`);
        }
        console.log();
    });

// ── Command: info ─────────────────────────────────────────
program
    .command('info <file>')
    .description('Parse and display ELF/PE binary headers')
    .option('-s, --sections', 'Show section details')
    .option('--headers', 'Show all headers')
    .option('-j, --json', 'Output as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const parser = new BinaryParser();
        const detector = new FileDetector();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
        }

        const detection = detector.detect(data);

        try {
            if (detection.type === 'elf') {
                const elf = parser.parseELF(data);
                if (opts.json) {
                    console.log(JSON.stringify(elf, null, 2));
                    return;
                }

                printSectionHeader('ELF Header');
                const h = elf.header;
                console.log(`  ${chalk.cyan('Class:')}        ${h.class === 2 ? 'ELF64' : 'ELF32'}`);
                console.log(`  ${chalk.cyan('Endianness:')}   ${h.endianness === 1 ? 'Little Endian' : 'Big Endian'}`);
                console.log(`  ${chalk.cyan('OS/ABI:')}       ${h.osabi || 0}`);
                console.log(`  ${chalk.cyan('Type:')}         ${h.typeStr || h.type || 'Unknown'}`);
                console.log(`  ${chalk.cyan('Machine:')}      ${chalk.yellow(h.machineStr || 'Unknown')} (${h.machine || 0})`);
                console.log(`  ${chalk.cyan('Entry Point:')}  ${chalk.yellow('0x' + (h.entryPoint || 0).toString(16))}`);
                console.log(`  ${chalk.cyan('PH Offset:')}    0x${(h.phOffset || 0).toString(16)}`);
                console.log(`  ${chalk.cyan('SH Offset:')}    0x${(h.shOffset || 0).toString(16)}`);
                console.log(`  ${chalk.cyan('Flags:')}        0x${(h.flags || 0).toString(16)}`);
                console.log(`  ${chalk.cyan('PH Count:')}     ${h.phNum || 0}`);
                console.log(`  ${chalk.cyan('SH Count:')}     ${h.shNum || 0}`);

                if (opts.sections || opts.headers) {
                    if (elf.programHeaders && elf.programHeaders.length > 0) {
                        printSectionHeader('Program Headers (Segments)');
                        elf.programHeaders.forEach((ph, i) => {
                            console.log(`  ${chalk.gray(`${i}.`)} ${chalk.yellow((ph.typeStr || 'UNKNOWN').padEnd(14))} ${chalk.cyan('off=0x' + (ph.offset || 0).toString(16).padStart(8, '0'))}  ${chalk.cyan('vaddr=0x' + (ph.vaddr || 0).toString(16).padStart(8, '0'))}  ${chalk.gray('filesz=' + (ph.filesz || 0))}  ${chalk.gray('memsz=' + (ph.memsz || 0))}  ${chalk.green(ph.flagsStr || '')}`);
                        });
                    }

                    if (elf.sectionHeaders && elf.sectionHeaders.length > 0) {
                        printSectionHeader('Section Headers');
                        elf.sectionHeaders.forEach((sh, i) => {
                            const name = (sh.nameStr || sh.name || '').padEnd(20);
                            console.log(`  ${chalk.gray(`${i.toString().padStart(2)}.`)} ${chalk.white(name)} ${chalk.yellow((sh.typeStr || '').padEnd(14))} ${chalk.cyan('addr=0x' + (sh.addr || 0).toString(16).padStart(8, '0'))}  ${chalk.cyan('off=0x' + (sh.offset || 0).toString(16).padStart(6, '0'))}  ${chalk.gray('size=' + (sh.size || 0))}`);
                        });
                    }
                }

            } else if (detection.type === 'pe') {
                const pe = parser.parsePE(data);
                if (opts.json) {
                    console.log(JSON.stringify(pe, null, 2));
                    return;
                }

                printSectionHeader('PE Header');
                const fh = pe.fileHeader || {};
                const oh = pe.optionalHeader || {};
                console.log(`  ${chalk.cyan('Machine:')}      ${chalk.yellow(fh.machineStr || 'Unknown')} (0x${(fh.machine || 0).toString(16)})`);
                console.log(`  ${chalk.cyan('Format:')}       ${oh.magic === 0x20b ? 'PE32+ (64-bit)' : 'PE32 (32-bit)'}`);
                console.log(`  ${chalk.cyan('Sections:')}     ${fh.numberOfSections || 0}`);
                console.log(`  ${chalk.cyan('Timestamp:')}    ${fh.timeDateStamp ? new Date(fh.timeDateStamp * 1000).toISOString() : 'Unknown'}`);
                console.log(`  ${chalk.cyan('Entry Point:')} ${chalk.yellow('0x' + (oh.entryPoint || 0).toString(16))}`);
                console.log(`  ${chalk.cyan('Image Base:')}  0x${(oh.imageBase || 0).toString(16)}`);
                console.log(`  ${chalk.cyan('Subsystem:')}   ${oh.subsystemStr || oh.subsystem || 'Unknown'}`);

                if ((opts.sections || opts.headers) && pe.sections) {
                    printSectionHeader('Sections');
                    pe.sections.forEach((s, i) => {
                        console.log(`  ${chalk.gray(`${i}.`)} ${chalk.white((s.name || '').padEnd(10))} ${chalk.cyan('VA=0x' + (s.virtualAddress || 0).toString(16).padStart(8, '0'))}  ${chalk.gray('vsize=' + (s.virtualSize || 0))}  ${chalk.cyan('raw=0x' + (s.pointerToRawData || 0).toString(16).padStart(8, '0'))}  ${chalk.gray('rawsize=' + (s.sizeOfRawData || 0))}  ${chalk.green(s.characteristicsStr || '')}`);
                    });
                }

            } else {
                if (!opts.json) {
                    console.log(`\n  ${chalk.yellow('⚠')} File is not a recognized ELF or PE binary.`);
                    console.log(`  ${chalk.gray('  Detected type:')} ${chalk.cyan(detection.type || 'unknown')}`);
                    console.log(`  ${chalk.gray('  Use')} ${chalk.cyan('firmwarex detect --scan')} ${chalk.gray('to find embedded binaries.')}`);
                }
            }
        } catch (e) {
            console.error(chalk.red(`\n  ✖ Parse error: ${e.message}`));
        }
        console.log();
    });

// ── Command: convert ──────────────────────────────────────
program
    .command('convert <file>')
    .description('Convert Intel HEX / SREC / UF2 / DFU to raw binary')
    .option('-o, --output <file>', 'Output file path')
    .option('-f, --format <fmt>', 'Force format: ihex, srec, uf2, dfu, auto', 'auto')
    .option('-j, --json', 'Output info as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const decoder = new HexDecoder();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
            printSectionHeader('Format Conversion');
        }

        let format = opts.format;
        if (format === 'auto') {
            if (decoder.isTextFormat) {
                const textFmt = decoder.detectTextFormat(data);
                if (textFmt) format = textFmt;
            }
            if (format === 'auto') {
                // Check by extension
                const ext = path.extname(file).toLowerCase();
                if (ext === '.hex' || ext === '.ihex') format = 'ihex';
                else if (ext === '.srec' || ext === '.s19' || ext === '.s28' || ext === '.s37') format = 'srec';
                else if (ext === '.uf2') format = 'uf2';
                else if (ext === '.dfu') format = 'dfu';
            }
        }

        try {
            let result;
            switch (format) {
                case 'ihex':
                    const text = Buffer.from(data).toString('ascii');
                    result = decoder.decodeIntelHex(text);
                    if (!opts.json) {
                        console.log(`  ${chalk.green('✔')} Intel HEX decoded`);
                        console.log(`  ${chalk.cyan('Data Size:')}     ${chalk.yellow(formatSize(result.data.length))}`);
                        console.log(`  ${chalk.cyan('Start Address:')} ${chalk.yellow('0x' + (result.startAddress || 0).toString(16))}`);
                        if (result.regions) console.log(`  ${chalk.cyan('Regions:')}       ${chalk.yellow(result.regions.length)}`);
                    }
                    break;
                case 'srec':
                    const srecText = Buffer.from(data).toString('ascii');
                    result = decoder.decodeSRecord(srecText);
                    if (!opts.json) {
                        console.log(`  ${chalk.green('✔')} Motorola S-Record decoded`);
                        console.log(`  ${chalk.cyan('Data Size:')}     ${chalk.yellow(formatSize(result.data.length))}`);
                        console.log(`  ${chalk.cyan('Start Address:')} ${chalk.yellow('0x' + (result.startAddress || 0).toString(16))}`);
                    }
                    break;
                case 'uf2':
                    result = decoder.decodeUF2(data);
                    if (!opts.json) {
                        console.log(`  ${chalk.green('✔')} UF2 decoded`);
                        console.log(`  ${chalk.cyan('Data Size:')}     ${chalk.yellow(formatSize(result.data.length))}`);
                        console.log(`  ${chalk.cyan('Start Address:')} ${chalk.yellow('0x' + (result.startAddress || 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('Family ID:')}     ${chalk.yellow(result.familyName || '0x' + (result.familyId || 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('Blocks:')}        ${chalk.yellow(result.blockCount || 0)}`);
                    }
                    break;
                case 'dfu':
                    result = decoder.decodeDFU(data);
                    if (!opts.json) {
                        console.log(`  ${chalk.green('✔')} DFU suffix stripped`);
                        console.log(`  ${chalk.cyan('Data Size:')}   ${chalk.yellow(formatSize(result.data.length))}`);
                        console.log(`  ${chalk.cyan('Vendor ID:')}   ${chalk.yellow('0x' + (result.vendorId || 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('Product ID:')} ${chalk.yellow('0x' + (result.productId || 0).toString(16))}`);
                        console.log(`  ${chalk.cyan('DFU Version:')} ${chalk.yellow(result.dfuVersion || 'Unknown')}`);
                    }
                    break;
                default:
                    console.error(chalk.red(`  ✖ Cannot determine format. Use --format to specify.`));
                    process.exit(1);
            }

            if (result && result.data) {
                if (opts.json) {
                    const jsonOut = { ...result };
                    jsonOut.data = undefined;
                    jsonOut.dataSize = result.data.length;
                    console.log(JSON.stringify(jsonOut, null, 2));
                }

                if (opts.output) {
                    fs.writeFileSync(opts.output, Buffer.from(result.data));
                    if (!opts.json) console.log(`\n  ${chalk.green('✔')} Saved raw binary to: ${chalk.cyan(path.resolve(opts.output))}`);
                } else if (!opts.output && !opts.json) {
                    const defaultOut = file.replace(/\.[^.]+$/, '.bin');
                    fs.writeFileSync(defaultOut, Buffer.from(result.data));
                    console.log(`\n  ${chalk.green('✔')} Saved raw binary to: ${chalk.cyan(path.resolve(defaultOut))}`);
                }
            }
        } catch (e) {
            console.error(chalk.red(`  ✖ Conversion failed: ${e.message}`));
        }
        console.log();
    });

// ── Command: security ─────────────────────────────────────
program
    .command('security <file>')
    .description('Scan firmware for secrets, credentials, vulnerabilities & backdoors')
    .option('--severity <level>', 'Filter by minimum severity (critical, high, medium, low, info)', 'info')
    .option('--category <cat>', 'Filter by category (credential, private_key, api_key, backdoor, weak_crypto, etc.)')
    .option('--no-keys', 'Skip private key scanning')
    .option('--no-creds', 'Skip credential scanning')
    .option('--no-vulns', 'Skip vulnerable function scanning')
    .option('--no-network', 'Skip network/protocol scanning')
    .option('--no-backdoors', 'Skip backdoor pattern scanning')
    .option('--no-crypto', 'Skip weak crypto scanning')
    .option('--no-defaults', 'Skip default credential scanning')
    .option('--min-length <n>', 'Minimum string length for extraction', parseInt, 4)
    .option('-o, --output <file>', 'Save report to file')
    .option('--json', 'Output results as JSON')
    .action((file, opts) => {
        const data = loadFile(file);
        const analyzer = new SecurityAnalyzer();

        if (!opts.json) {
            console.log(banner);
            printFileInfo(file, data);
            printSectionHeader('🛡️  Security Analysis');
        }

        const options = {
            minStringLength: opts.minLength || 4,
            scanKeys: opts.keys !== false,
            scanCredentials: opts.creds !== false,
            scanApiKeys: true,
            scanVulnFunctions: opts.vulns !== false,
            scanNetwork: opts.network !== false,
            scanBackdoors: opts.backdoors !== false,
            scanCrypto: opts.crypto !== false,
            scanDefaultCreds: opts.defaults !== false,
            scanPaths: true
        };

        const result = analyzer.analyze(data, options);

        // Apply severity filter
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const minSev = sevOrder[opts.severity] !== undefined ? sevOrder[opts.severity] : 4;
        const findings = result.findings.filter(f => (sevOrder[f.severity] || 4) <= minSev);

        // Apply category filter
        const filtered = opts.category
            ? findings.filter(f => f.category === opts.category)
            : findings;

        if (opts.json) {
            console.log(JSON.stringify({
                riskScore: result.riskScore,
                summary: result.summary,
                stats: result.stats,
                findings: filtered
            }, null, 2));
        } else {
            // ── Risk Score Dashboard ────────────────────────────
            const score = result.riskScore;
            let riskColor, riskLabel;
            if (score >= 75)      { riskColor = chalk.red;    riskLabel = 'CRITICAL'; }
            else if (score >= 50) { riskColor = chalk.hex('#ff8c00'); riskLabel = 'HIGH'; }
            else if (score >= 25) { riskColor = chalk.yellow; riskLabel = 'MEDIUM'; }
            else if (score > 0)   { riskColor = chalk.cyan;   riskLabel = 'LOW'; }
            else                  { riskColor = chalk.green;   riskLabel = 'CLEAN'; }

            console.log();
            console.log(`  ┌─────────────────────────────────────────────────────┐`);
            console.log(`  │  Risk Score: ${riskColor(score.toString().padStart(3) + '/100')}   Level: ${riskColor(riskLabel.padEnd(10))}            │`);
            console.log(`  ├─────────────────────────────────────────────────────┤`);
            console.log(`  │  ${chalk.red('🔴 Critical: ' + String(result.stats.critical).padEnd(4))} ${chalk.hex('#ff8c00')('🟠 High: ' + String(result.stats.high).padEnd(4))} ${chalk.yellow('🟡 Medium: ' + String(result.stats.medium).padEnd(4))} │`);
            console.log(`  │  ${chalk.cyan('🔵 Low: ' + String(result.stats.low).padEnd(8))} ${chalk.gray('⚪ Info: ' + String(result.stats.info).padEnd(4))}                    │`);
            console.log(`  │  ${chalk.white('Total Findings: ' + result.stats.total)}                                │`);
            console.log(`  └─────────────────────────────────────────────────────┘`);
            console.log();

            if (filtered.length === 0) {
                console.log(chalk.green('  ✔ No security issues found matching your criteria.'));
            } else {
                // ── Category Summary ────────────────────────────────
                if (result.summary && result.summary.categories) {
                    printSectionHeader('Category Breakdown');
                    const cats = result.summary.categories;
                    const catLabels = {
                        credential: '🔑 Credentials', private_key: '🗝️  Private Keys', api_key: '🔐 API Keys',
                        token: '🎫 Tokens', secret: '🤫 Secrets', backdoor: '🚪 Backdoors',
                        vulnerable_function: '⚠️  Unsafe Functions', weak_crypto: '🔓 Weak Crypto',
                        buffer_overflow: '💥 Buffer Overflow', command_injection: '💉 Cmd Injection',
                        format_string: '📝 Format String', insecure_protocol: '🌐 Insecure Protocols',
                        hardcoded_ip: '📡 Hardcoded IPs', sensitive_path: '📁 Sensitive Paths',
                        default_credential: '👤 Default Creds', certificate: '📜 Certificates',
                        info_leak: 'ℹ️  Info Leaks', debug_info: '🐛 Debug Info', network: '🌐 Network'
                    };
                    Object.keys(cats).forEach(cat => {
                        const label = catLabels[cat] || cat;
                        const bar = '█'.repeat(Math.min(cats[cat], 40));
                        console.log(`  ${label.padEnd(28)} ${chalk.cyan(bar)} ${cats[cat]}`);
                    });
                    console.log();
                }

                // ── Findings Detail ─────────────────────────────────
                printSectionHeader(`Findings (${filtered.length})`);

                filtered.forEach((f, idx) => {
                    const fmt = analyzer.formatFinding(f);
                    let sevStr;
                    switch (f.severity) {
                        case 'critical': sevStr = chalk.bgRed.white.bold(` ${fmt.severity} `); break;
                        case 'high':     sevStr = chalk.bgHex('#ff8c00').white.bold(` ${fmt.severity}     `); break;
                        case 'medium':   sevStr = chalk.bgYellow.black.bold(` ${fmt.severity}   `); break;
                        case 'low':      sevStr = chalk.bgCyan.black.bold(` ${fmt.severity}      `); break;
                        default:         sevStr = chalk.bgGray.white(` ${fmt.severity}     `); break;
                    }

                    console.log(`  ${chalk.gray(`[${(idx + 1).toString().padStart(3)}]`)} ${sevStr}  ${chalk.white.bold(f.name)}`);
                    console.log(`        ${chalk.gray('Category:')} ${f.category}`);
                    if (f.cwe) console.log(`        ${chalk.gray('CWE:')}      ${chalk.cyan(f.cwe)}`);
                    console.log(`        ${chalk.gray(f.description)}`);
                    if (fmt.offset) console.log(`        ${chalk.gray('Offset:')}   ${chalk.yellow(fmt.offset)}`);
                    if (f.evidence) {
                        const evidence = f.evidence.length > 100 ? f.evidence.substring(0, 100) + '...' : f.evidence;
                        console.log(`        ${chalk.gray('Evidence:')} ${chalk.dim(evidence)}`);
                    }
                    console.log();
                });
            }

            // Save report if requested
            if (opts.output) {
                let report = `FirmwareX Security Report\n${'='.repeat(60)}\n`;
                report += `File: ${path.resolve(file)}\n`;
                report += `Date: ${new Date().toISOString()}\n`;
                report += `Risk Score: ${score}/100 (${riskLabel})\n`;
                report += `Total: ${result.stats.total}  Critical: ${result.stats.critical}  High: ${result.stats.high}  Medium: ${result.stats.medium}  Low: ${result.stats.low}  Info: ${result.stats.info}\n`;
                report += `${'='.repeat(60)}\n\n`;

                filtered.forEach((f, i) => {
                    report += `[${(i + 1).toString().padStart(3)}] ${f.severity.toUpperCase()} — ${f.name}\n`;
                    report += `      Category: ${f.category}\n`;
                    if (f.cwe) report += `      CWE: ${f.cwe}\n`;
                    report += `      ${f.description}\n`;
                    if (f.offset !== undefined) report += `      Offset: 0x${f.offset.toString(16)}\n`;
                    if (f.evidence) report += `      Evidence: ${f.evidence.substring(0, 150)}\n`;
                    report += `\n`;
                });

                fs.writeFileSync(opts.output, report);
                console.log(`  ${chalk.green('✔')} Report saved to: ${chalk.cyan(path.resolve(opts.output))}`);
            }
        }
        console.log();
    });

// ── Parse & Run ───────────────────────────────────────────
program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
    console.log(banner);
    program.outputHelp();
}
