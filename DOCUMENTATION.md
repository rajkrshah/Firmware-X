# Firmware-X Documentation

Welcome to the technical documentation for **Firmware-X (v1.0.0)**. This document provides a detailed breakdown of the internal architecture, specifically focusing on the specialized analysis modules that power the tool.

## Architecture Overview

Firmware-X is built using a hybrid architecture:
1. **Frontend UI Engine**: A lightweight, vanilla JavaScript and HTML5 application capable of handling massive files (8GB+) natively in the browser using streaming and chunking techniques.
2. **Backend Services**: A Node.js and Express server that handles complex operations (like SquashFS extraction and deep secret scanning) that require native system binaries.

The core logic of the application is compartmentalized into highly specialized modules located in the `/modules` directory.

---

## Detailed Module Breakdown

### 1. `file-detector.js`
**Purpose**: Identifies file types, architectures, and byte-order (endianness) without relying on file extensions.
**How it Works**: 
- It reads the first few bytes (the "magic bytes") of the binary to detect file types at offset 0.
- It provides a `scanAll()` method that uses an optimized first-byte lookup table to rapidly scan massive binaries byte-by-byte, identifying embedded signatures at any offset without performance degradation.
- It compares these bytes against a vast internal library of known file signatures (e.g., `7F 45 4C 46` for ELF, `50 4B 03 04` for ZIP, `68 73 71 73` for SquashFS).
- It returns high-confidence metadata that dictates how downstream modules should handle the file.

### 2. `entropy-analyzer.js`
**Purpose**: Detects packed, compressed, or encrypted regions within the firmware.
**How it Works**:
- It uses Shannon Entropy calculations (measuring the randomness of data on a scale of 0 to 8).
- The file is chunked into small sliding windows (e.g., 256 bytes or 1KB).
- An entropy score of ~8.0 implies the data is highly random (encrypted or heavily compressed). A low score implies empty space or plain text. 
- The module returns an array of coordinates that powers the visual Entropy Map graph in the UI.

### 3. `archive-extractor.js`
**Purpose**: Extracts nested filesystems and compressed archives natively in the browser.
**How it Works**:
- Works closely with `layer-engine.js`. When a supported archive (ZIP, GZIP, TAR) is detected, it delegates extraction entirely to browser-side libraries (like `fflate` and `JSZip`) to keep data local.

### 4. `binary-parser.js`
**Purpose**: Parses the structural headers of executable formats (ELF for Linux, PE for Windows).
**How it Works**:
- For ELF files, it maps out the ELF Header, Program Headers (segments), and Section Headers (e.g., `.text`, `.rodata`, `.bss`).
- It extracts entry points, linked libraries, and execution architectures (e.g., x86_64, ARM, MIPS), which are crucial for the disassembler.

### 5. `disassembler.js`
**Purpose**: Translates raw machine code bytes into human-readable assembly language.
**How it Works**:
- Given the architecture (auto-detected or manually set), it maps hexadecimal opcodes to their corresponding assembly instructions (mnemonics and operands).
- It relies on a WebAssembly (WASM) build of the Capstone engine (`capstone-wasm`). To conserve memory and bandwidth, this engine is **lazy-loaded dynamically** from a CDN only when a disassembly preview or full download is explicitly requested.

### 6. `string-extractor.js`
**Purpose**: Extracts human-readable text hidden within the binary.
**How it Works**:
- Iterates over the raw binary looking for contiguous sequences of printable ASCII or UTF-16 characters (defaulting to a minimum length of 4).
- Applies Regex heuristics to automatically categorize the strings into actionable groups such as `URLs`, `File Paths`, `Emails`, `IP Addresses`, and `Crypto Certificates`.

### 7. `security-analyzer.js`
**Purpose**: The static heuristic engine for detecting common vulnerabilities.
**How it Works**:
- It scans the raw bytes and extracted strings for dangerous patterns, such as insecure network protocols (e.g., `http://`, `telnet`), dangerous function calls (e.g., `strcpy`, `system`), and format string vulnerabilities.
- **Categorization**: It automatically tags all findings with an industry-standard **CWE (Common Weakness Enumeration)** identifier using an intelligent fallback mapping system based on the vulnerability category.
- **Scoring**: It calculates an overall Risk Score on a standard **CVSS v3.1** qualitative scale (0.0 to 10.0). The overall asset score is determined using an Aggregated Max-Score model (taking the highest base CVSS score found in the firmware).

### 8. `secret-scanner.js` & Extraction APIs (Backend)
**Purpose**: Deep scanning for hardcoded secrets, and native binary extraction.
**How it Works**:
- Runs in Node.js to circumvent browser memory limits for complex tasks.
- **Secret Scanner**: Uses chunk-based streams to process multi-gigabyte firmware images, applying complex Regex patterns to detect AWS keys, SSH keys, etc.
- **Binwalk API**: The `/api/extract` route directly runs native `binwalk` via `execSync` (routing through `wsl` on Windows automatically), streaming output and extracted file trees directly back to the browser UI without spawning external GUI terminal windows.

### 9. `decryption-engine.js`
**Purpose**: Analyzes and defeats basic obfuscation and encryption techniques.
**How it Works**:
- Uses statistical analysis (like frequency analysis) to detect repeating patterns characteristic of XOR encryption.
- It can auto-detect repeating XOR keys and apply the inverse operation on the fly to reveal hidden payloads without requiring the user to manually guess the key.

### 10. `layer-engine.js`
**Purpose**: Manages the abstraction of nested files.
**How it Works**:
- Firmware is rarely a single flat file. It is often a zip file containing a tarball containing an ext4 filesystem containing an ELF binary. 
- The Layer Engine tracks this hierarchy by initially checking offset 0, and then performing a **Deep Scan** across the entire binary to locate embedded partitions (SquashFS, JFFS2) and executables at arbitrary offsets, automatically linking them as child layers.

### 11. `hex-viewer.js`
**Purpose**: The rendering engine for the massive hexadecimal view.
**How it Works**:
- Rendering a 1GB file in the browser's DOM would crash it instantly. 
- This module implements "Virtual Scrolling". It only renders the exact 30-40 rows of Hex currently visible on your screen, instantly calculating and rendering new rows as you scroll, allowing for lag-free exploration of gigabyte-sized files.
- It also handles the high-speed binary search algorithms.

### 12. `hex-decoder.js`
**Purpose**: A localized helper for translating specific hex blocks into various data types.
**How it Works**:
- Converts user-selected bytes in the Hex Viewer into different representations (Int8, Uint32, Float, Base64, etc.), helping analysts quickly decode hardcoded variables and structures.

---

## Workflow Integration
When a file is dragged into Firmware-X, the modules orchestrate in the following sequence:
1. `file-detector` identifies it.
2. `entropy-analyzer` maps it.
3. `string-extractor` pulls the text.
4. `binary-parser` maps the executable sections (if applicable).
5. `security-analyzer` runs a static pass.
6. The user interacts with the results via `hex-viewer`, `disassembler`, and backend tools like `secret-scanner` for deeper inspection.
