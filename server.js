#!/usr/bin/env node
/**
 * FirmwareX — Local Web Server
 * Serves the firmware analysis web UI on localhost
 * Cross-platform: Windows + Linux + macOS
 */

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const isDev = process.argv.includes('--dev');

const banner = `
\x1b[36m╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║   ███████╗██╗██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗        ██╗  ██╗   ║
║   ██╔════╝██║██╔══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝        ╚██╗██╔╝   ║
║   █████╗  ██║██████╔╝██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗  ███████╗ ╚███╔╝    ║
║   ██╔══╝  ██║██╔══██╗██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝  ╚══════╝ ██╔██╗    ║
║   ██║     ██║██║  ██║██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗        ██╔╝ ██╗   ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝        ╚═╝  ╚═╝   ║
║                                                                                      ║
║   Firmware Analysis Tool v1.0.0                                                      ║
║   100% Local Processing — Your Data Stays Yours                                      ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝\x1b[0m
`;

// ── Middleware ─────────────────────────────────────────────
app.use((req, res, next) => {
    // CORS for local development
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-File-Name');
    next();
});

// Increase payload limit for smaller JSON requests
app.use(express.json({ limit: '50mb' }));
// We remove the global express.raw() here to prevent OOM crashes on 200MB+ files.
// Large binary routes will now stream directly to disk!

// ── Static File Routes ────────────────────────────────────

// Serve public/ directory (HTML, CSS, app.js)
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: isDev ? 0 : '1h'
}));

// Serve modules/ directory
app.use('/modules', express.static(path.join(__dirname, 'modules'), {
    maxAge: isDev ? 0 : '1h'
}));

// Serve bundled libraries from public/lib/
app.use('/lib', express.static(path.join(__dirname, 'public', 'lib'), {
    maxAge: isDev ? 0 : '1d'
}));

// Fallback: serve fflate from node_modules if not copied to public/lib
app.get('/lib/fflate.min.js', (req, res) => {
    const paths = [
        path.join(__dirname, 'public', 'lib', 'fflate.min.js'),
        path.join(__dirname, 'node_modules', 'fflate', 'umd', 'index.js'),
        path.join(__dirname, 'node_modules', 'fflate', 'dist', 'fflate.umd.js')
    ];
    for (const p of paths) {
        if (fs.existsSync(p)) {
            return res.sendFile(p);
        }
    }
    res.status(404).send('fflate library not found. Run install script first.');
});

// Fallback: serve JSZip from node_modules if not copied
app.get('/lib/jszip.min.js', (req, res) => {
    const paths = [
        path.join(__dirname, 'public', 'lib', 'jszip.min.js'),
        path.join(__dirname, 'node_modules', 'jszip', 'dist', 'jszip.min.js')
    ];
    for (const p of paths) {
        if (fs.existsSync(p)) {
            return res.sendFile(p);
        }
    }
    res.status(404).send('JSZip library not found. Run install script first.');
});

// ── API Routes ────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        version: '1.0.0',
        platform: process.platform,
        nodeVersion: process.version,
        uptime: process.uptime()
    });
});

// Get supported architectures info
app.get('/api/architectures', (req, res) => {
    res.json({
        supported: [
            { name: 'x86', modes: ['16-bit', '32-bit', '64-bit'], description: 'Intel/AMD x86 family' },
            { name: 'ARM', modes: ['ARM', 'Thumb'], description: 'ARM 32-bit' },
            { name: 'ARM64', modes: ['Default'], description: 'ARM 64-bit (AArch64)' },
            { name: 'MIPS', modes: ['MIPS32', 'MIPS64', 'MicroMIPS'], description: 'MIPS family' },
            { name: 'PowerPC', modes: ['32-bit', '64-bit'], description: 'IBM PowerPC' },
            { name: 'SPARC', modes: ['V8', 'V9'], description: 'Oracle SPARC' },
            { name: 'SystemZ', modes: ['Default'], description: 'IBM System/390' },
            { name: 'M68K', modes: ['68000-68060'], description: 'Motorola 68000' },
            { name: 'XCore', modes: ['Default'], description: 'XMOS XCore' },
            { name: 'TMS320C6x', modes: ['Default'], description: 'TI C6000 DSP' },
            { name: 'M680x', modes: ['Default'], description: 'Motorola/Freescale M680x' },
            { name: 'EVM', modes: ['Default'], description: 'Ethereum Virtual Machine' }
        ]
    });
});

// ── Firmware CLI Extraction API ───────────────────────────
app.post('/api/extract', async (req, res) => {
    const { execSync } = require('child_process');
    const crypto = require('crypto');

    const workspaceDir = path.join(__dirname, 'workspace');
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir, { recursive: true });

    const origName = req.headers['x-file-name'] || 'firmware.bin';
    const safeName = origName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const sessionId = crypto.randomBytes(4).toString('hex');
    const targetFile = sessionId + '_' + safeName;
    const targetPath = path.join(workspaceDir, targetFile);

    try {
        // Stream the incoming binary directly to disk
        const writeStream = fs.createWriteStream(targetPath);
        req.pipe(writeStream);

        await new Promise(function(resolve, reject) {
            writeStream.on('finish', resolve);
            writeStream.on('error', reject);
            req.on('error', reject);
        });

        // Verify file was written
        if (!fs.existsSync(targetPath) || fs.statSync(targetPath).size === 0) {
            return res.status(500).json({ success: false, error: 'File upload failed. Empty or missing file on disk.', output: '' });
        }

        var fileSize = fs.statSync(targetPath).size;
        var output = '[System] File saved: ' + targetFile + ' (' + fileSize + ' bytes)\n';
        var isWin = process.platform === 'win32';

        // Check if binwalk is available
        try {
            execSync(isWin ? 'wsl which binwalk' : 'which binwalk', { timeout: 5000 });
        } catch (whichErr) {
            output += '[Error] binwalk is not installed or not in PATH.\n';
            output += '[Help] Install it with: sudo apt install binwalk\n';
            return res.status(500).json({ success: false, error: 'binwalk is not installed. Run: sudo apt install binwalk', output: output });
        }

        var cmdStr = isWin ? 'wsl binwalk -Me "' + targetFile + '"' : 'binwalk -Me "' + targetFile + '"';
        output += '[System] binwalk found. Running: ' + cmdStr + '\n';
        output += '[System] Working directory: ' + workspaceDir + '\n\n';

        // Run binwalk with 120s timeout
        try {
            var cmdResult = execSync(cmdStr, {
                cwd: workspaceDir,
                timeout: 120000,
                maxBuffer: 1024 * 1024 * 50,
                encoding: 'utf-8'
            });
            output += cmdResult + '\n';
            output += '\n[System] Extraction completed successfully!\n';
        } catch (execErr) {
            output += (execErr.stdout || '') + '\n';
            output += (execErr.stderr || '') + '\n';
            if (execErr.killed) {
                output += '[Warning] binwalk timed out after 120s.\n';
            }
        }

        // List extracted directories
        var allEntries = fs.readdirSync(workspaceDir);
        var extractedDirs = allEntries.filter(function(f) {
            var fp = path.join(workspaceDir, f);
            try { return fs.statSync(fp).isDirectory() && f.indexOf(targetFile) !== -1; } catch(e) { return false; }
        });

        if (extractedDirs.length > 0) {
            output += '[System] Extracted directory: ' + extractedDirs[0] + '\n';
            try {
                var fileList = [];
                var walkDir = function(dir, prefix, depth) {
                    if (depth > 3) return;
                    var entries = fs.readdirSync(dir);
                    var limit = Math.min(entries.length, 30);
                    for (var i = 0; i < limit; i++) {
                        var fullPath = path.join(dir, entries[i]);
                        var stat = fs.statSync(fullPath);
                        if (stat.isDirectory()) {
                            fileList.push(prefix + entries[i] + '/');
                            walkDir(fullPath, prefix + '  ', depth + 1);
                        } else {
                            fileList.push(prefix + entries[i] + ' (' + stat.size + ' bytes)');
                        }
                    }
                    if (entries.length > 30) fileList.push(prefix + '... and ' + (entries.length - 30) + ' more');
                };
                walkDir(path.join(workspaceDir, extractedDirs[0]), '  ', 0);
                output += '[System] Extracted file tree:\n' + fileList.join('\n') + '\n';
            } catch (listErr) { /* ignore */ }
            res.json({ success: true, outDir: path.join(workspaceDir, extractedDirs[0]), output: output });
        } else {
            output += '[System] No extracted directory found. The firmware may not contain extractable filesystems.\n';
            res.json({ success: true, outDir: workspaceDir, output: output });
        }
    } catch (e) {
        console.error('Extract API error:', e);
        res.status(500).json({ success: false, error: e.message, output: '' });
    }
});

// ── Secret Scanner API ──────────────────────────────────────
app.post('/api/scan-secrets', async (req, res) => {
    const crypto = require('crypto');
    const SecretScanner = require('./modules/secret-scanner');
    
    const workspaceDir = path.join(__dirname, 'workspace');
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir);

    const sessionId = crypto.randomBytes(4).toString('hex');
    const targetFile = `scan_${sessionId}.bin`;
    const targetPath = path.join(workspaceDir, targetFile);

    try {
        const writeStream = fs.createWriteStream(targetPath);
        req.pipe(writeStream);
        
        await new Promise((resolve, reject) => {
            writeStream.on('finish', resolve);
            writeStream.on('error', reject);
            req.on('error', reject);
        });

        // Scan the file
        const findings = await SecretScanner.scanFile(targetPath);
        
        // Clean up the temporary scan file to save space
        try { fs.unlinkSync(targetPath); } catch(e) {}
        
        res.json({ success: true, findings });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ── Full Disassembly Streaming API ────────────────────────
app.post('/api/disasm-upload', (req, res) => {
    const crypto = require('crypto');
    const sessionId = crypto.randomBytes(8).toString('hex');
    const workspaceDir = path.join(__dirname, 'workspace');
    if (!fs.existsSync(workspaceDir)) fs.mkdirSync(workspaceDir);
    
    const targetFile = path.join(workspaceDir, `${sessionId}.bin`);
    
    // Stream directly to disk to bypass Node V8 memory limits on large files
    const writeStream = fs.createWriteStream(targetFile);
    req.pipe(writeStream);
    
    writeStream.on('finish', () => {
        res.json({ sessionId });
    });
    
    writeStream.on('error', (err) => {
        res.status(500).json({ error: err.message });
    });
    
    req.on('error', (err) => {
        writeStream.destroy();
        res.status(500).json({ error: err.message });
    });
});

app.get('/api/disasm-download/:sessionId', async (req, res) => {
    const { sessionId } = req.params;
    const { arch, mode } = req.query;
    const targetFile = path.join(__dirname, 'workspace', `${sessionId}.bin`);
    
    if (!fs.existsSync(targetFile)) {
        return res.status(404).send('Session expired or file not found');
    }
    
    res.setHeader('Content-Disposition', `attachment; filename="firmware_${arch || 'auto'}.asm"`);
    res.setHeader('Content-Type', 'text/plain');
    
    try {
        const Disassembler = require('./modules/disassembler');
        const buffer = fs.readFileSync(targetFile);
        const dataArray = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        
        const disassembler = new Disassembler();
        await disassembler.init(); // Requires the Capstone WASM bundle
        
        const CHUNK_SIZE = 4096;
        let currentOffset = 0;
        let baseAddr = 0;
        
        let parsedArch = parseInt(arch) || disassembler.ARCH.X86;
        let parsedMode = parseInt(mode) || disassembler.MODE['32'];
        
        while (currentOffset < dataArray.length) {
            const chunk = dataArray.slice(currentOffset, currentOffset + CHUNK_SIZE);
            const result = disassembler.disassemble(chunk, parsedArch, parsedMode, baseAddr, { maxInstructions: 1000 });
            
            let bytesConsumed = 0;
            let outText = '';
            
            for (const insn of result.instructions) {
                const bArr = Array.from(insn.bytes);
                bytesConsumed += bArr.length;
                outText += `0x${insn.address.toString(16).padStart(8, '0')}:  ${bArr.map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(24)} ${insn.mnemonic.padEnd(8)} ${insn.op_str}\n`;
            }
            
            if (bytesConsumed === 0) {
                bytesConsumed = 1;
                outText += `0x${baseAddr.toString(16).padStart(8, '0')}:  ${chunk[0].toString(16).padStart(2, '0').padEnd(24)} .byte    0x${chunk[0].toString(16).padStart(2, '0')}\n`;
            }
            
            // Write to stream. If the network buffer is full, wait for it to drain!
            if (!res.write(outText)) {
                await new Promise(resolve => res.once('drain', resolve));
            } else if (currentOffset % (CHUNK_SIZE * 10) === 0) {
                // Yield the event loop periodically so the server doesn't freeze
                await new Promise(resolve => setImmediate(resolve));
            }
            
            currentOffset += bytesConsumed;
            baseAddr += bytesConsumed;
        }
    } catch (e) {
        res.write(`\n\nERROR OCCURRED DURING STREAMING: ${e.message}\n`);
    } finally {
        res.end();
        fs.unlinkSync(targetFile); // Cleanup
    }
});

// ── SPA Fallback ──────────────────────────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start Server ──────────────────────────────────────────
let currentPort = PORT;
let server;

const startServer = () => {
    server = app.listen(currentPort, async () => {
        console.log(banner);
        console.log(`\x1b[32m  ✔ Server running at:\x1b[0m  \x1b[36mhttp://localhost:${currentPort}\x1b[0m`);
        console.log(`\x1b[32m  ✔ Platform:\x1b[0m          \x1b[33m${process.platform}\x1b[0m`);
        console.log(`\x1b[32m  ✔ Node.js:\x1b[0m           \x1b[33m${process.version}\x1b[0m`);
        console.log(`\x1b[32m  ✔ Mode:\x1b[0m              \x1b[33m${isDev ? 'Development' : 'Production'}\x1b[0m`);
        console.log();
        console.log(`\x1b[90m  Press Ctrl+C to stop the server\x1b[0m`);
        console.log();

        try {
            const open = require('open');
            await open(`http://localhost:${currentPort}`);
            console.log(`\x1b[32m  ✔ Browser opened automatically\x1b[0m`);
        } catch (e) {
            console.log(`\x1b[33m  ⚠ Open http://localhost:${currentPort} in your browser\x1b[0m`);
        }
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.log(`\n  \x1b[33m⚠️  Port ${currentPort} is already in use (probably by the old python server). Trying port ${currentPort + 1}...\x1b[0m`);
            currentPort++;
            startServer();
        } else {
            console.error(err);
        }
    });
};

startServer();

// ── Graceful Shutdown ─────────────────────────────────────
function shutdown() {
    console.log('\n\x1b[33m  Shutting down FirmwareX server...\x1b[0m');
    if (server) {
        server.close(() => {
            console.log('\x1b[32m  ✔ Server stopped gracefully\x1b[0m\n');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
    setTimeout(() => process.exit(1), 5000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

if (process.platform === 'win32') {
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    rl.on('SIGINT', shutdown);
}
