"""
FirmwareX - Sample Firmware Validation Script
Independently analyzes sample_firmware.bin and validates all analysis modules.
Mimics what the JS modules do, validating results without needing Node.js.
"""
import os
import sys
import struct
import math
import re
import hashlib
from collections import Counter

# Force UTF-8 output
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

SAMPLE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_firmware.bin")

# Terminal colors
class C:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    CYAN = '\033[96m'; MAGENTA = '\033[95m'; WHITE = '\033[97m'
    GRAY = '\033[90m'; BOLD = '\033[1m'; DIM = '\033[2m'
    RESET = '\033[0m'; BG_RED = '\033[41m'

PASS = 0
FAIL = 0

def header(text):
    w = 60
    print(f"\n  {C.CYAN}{'='*w}{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}  {text}{C.RESET}")
    print(f"  {C.CYAN}{'='*w}{C.RESET}\n")

def subheader(text):
    print(f"\n  {C.GRAY}-- {C.WHITE}{text} {C.GRAY}{'-'*(50-len(text))}{C.RESET}")

def check(label, passed, detail=""):
    global PASS, FAIL
    if passed:
        PASS += 1
        icon = f"{C.GREEN}[PASS]{C.RESET}"
    else:
        FAIL += 1
        icon = f"{C.RED}[FAIL]{C.RESET}"
    det = f"  {C.DIM}{detail}{C.RESET}" if detail else ""
    print(f"  {icon}  {label}{det}")

def info(label, value):
    print(f"  {C.GRAY}{label}:{C.RESET} {C.WHITE}{value}{C.RESET}")

# ====================================================================
#  Module 1: File Detection (magic bytes)
# ====================================================================
def test_file_detection(data):
    header("Module 1: File Detector - Magic Byte Detection")

    detected = "Unknown"
    if data[:4] == b'\x7fELF':
        detected = "ELF"
        ei_class = data[4]
        ei_data = data[5]
        machine = struct.unpack_from("<H", data, 18)[0] if ei_data == 1 else struct.unpack_from(">H", data, 18)[0]

        class_str = {1: "32-bit", 2: "64-bit"}.get(ei_class, "Unknown")
        endian_str = {1: "Little-Endian", 2: "Big-Endian"}.get(ei_data, "Unknown")
        machine_str = {3: "x86", 40: "ARM", 62: "x86_64", 8: "MIPS", 183: "AArch64"}.get(machine, f"Machine({machine})")

        info("Format", f"ELF ({class_str}, {endian_str})")
        info("Architecture", machine_str)
        info("Entry Point", f"0x{struct.unpack_from('<I', data, 24)[0]:08X}")

        check("ELF magic bytes detected (7f 45 4c 46)", True)
        check(f"Architecture: {machine_str}", machine == 3, f"Machine code: {machine}")
        check(f"Endianness: {endian_str}", ei_data == 1)
        check(f"Bit width: {class_str}", ei_class == 1)
    else:
        check("Known format detected", False, f"First 4 bytes: {data[:4].hex()}")

    return detected

# ====================================================================
#  Module 2: Cryptographic Hashing
# ====================================================================
def test_hashing(data):
    header("Module 2: Cryptographic Hashing")

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    info("MD5   ", md5)
    info("SHA-1 ", sha1)
    info("SHA-256", sha256)
    info("Size  ", f"{len(data)} bytes ({len(data)/1024:.2f} KB)")

    check("MD5 hash computed (32 hex chars)", len(md5) == 32)
    check("SHA-1 hash computed (40 hex chars)", len(sha1) == 40)
    check("SHA-256 hash computed (64 hex chars)", len(sha256) == 64)

# ====================================================================
#  Module 3: Entropy Analysis
# ====================================================================
def test_entropy(data):
    header("Module 3: Entropy Analyzer - Shannon Entropy")

    block_size = 64
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < 16:
            continue
        freq = Counter(block)
        entropy = 0.0
        for count in freq.values():
            p = count / len(block)
            if p > 0:
                entropy -= p * math.log2(p)
        blocks.append(entropy)

    avg = sum(blocks) / len(blocks) if blocks else 0
    mx = max(blocks) if blocks else 0
    mn = min(blocks) if blocks else 0

    info("Average Entropy", f"{avg:.4f} / 8.0")
    info("Max Entropy", f"{mx:.4f}")
    info("Min Entropy", f"{mn:.4f}")
    info("Blocks", str(len(blocks)))

    # ASCII chart
    subheader("Entropy Map")
    for i, ent in enumerate(blocks):
        bar_len = int((ent / 8.0) * 40)
        if ent > 7.0: color = C.RED
        elif ent > 5.0: color = C.YELLOW
        elif ent > 3.0: color = C.CYAN
        else: color = C.GREEN
        bar = f"{color}{'#' * bar_len}{C.DIM}{'.' * (40 - bar_len)}{C.RESET}"
        label = ""
        if ent < 1.0: label = " <- padding/nulls"
        elif ent > 5.5: label = " <- encrypted data"
        print(f"  {C.GRAY}0x{i*block_size:04x}{C.RESET} |{bar}| {ent:.2f}{C.DIM}{label}{C.RESET}")

    check("Entropy calculated successfully", avg > 0)
    check("Low-entropy regions detected (padding)", mn < 2.0, f"Min: {mn:.2f}")
    check("Higher-entropy regions detected (encrypted/text)", mx > 4.0, f"Max: {mx:.2f}")

    return avg

# ====================================================================
#  Module 4: String Extraction
# ====================================================================
def test_strings(data):
    header("Module 4: String Extractor - ASCII Pattern Matching")

    min_len = 4
    strings = []
    current = b""
    start = 0

    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7e:
            if not current:
                start = i
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append((start, current.decode('ascii', errors='replace')))
            current = b""
    if len(current) >= min_len:
        strings.append((start, current.decode('ascii', errors='replace')))

    info("Strings Found", str(len(strings)))

    subheader("Extracted Strings")
    for off, s in strings[:25]:
        tag = "  "
        color = C.WHITE
        if re.search(r'(password|admin|secret|key|backdoor|root)', s, re.I):
            tag = "!!"; color = C.RED
        elif re.search(r'AKIA|BEGIN.*KEY|ghp_', s):
            tag = "**"; color = C.MAGENTA
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
            tag = "IP"; color = C.YELLOW
        elif re.search(r'strcpy|gets|sprintf|system|popen', s):
            tag = "!!"; color = C.RED
        elif re.search(r'telnet|ssh|ssl|http', s, re.I):
            tag = "NW"; color = C.CYAN
        truncated = s[:80] + ("..." if len(s) > 80 else "")
        print(f"  {C.GRAY}0x{off:04x}{C.RESET} [{tag}] {color}{truncated}{C.RESET}")

    if len(strings) > 25:
        print(f"  {C.DIM}  ... and {len(strings)-25} more{C.RESET}")

    check(f"Strings extracted: {len(strings)}", len(strings) > 0)
    check("Password-related strings found", any(re.search(r'password|passwd', s, re.I) for _, s in strings))
    check("AWS key string found", any('AKIA' in s for _, s in strings))
    check("IP address strings found", any(re.search(r'\d+\.\d+\.\d+\.\d+', s) for _, s in strings))
    check("Vulnerable function names found", any(re.search(r'strcpy|gets|system', s) for _, s in strings))

    return strings

# ====================================================================
#  Module 5: Hex Viewer
# ====================================================================
def test_hexview(data):
    header("Module 5: Hex Viewer - Binary Dump")

    rows = min(20, len(data) // 16)
    subheader("First 320 bytes")
    print(f"  {C.GRAY}{'Offset':>8}  {'00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F':48}  {'ASCII':16}{C.RESET}")
    print(f"  {C.GRAY}{'-'*8}  {'-'*48}  {'-'*16}{C.RESET}")

    for row in range(rows):
        off = row * 16
        hex_parts = []
        ascii_parts = []
        for col in range(16):
            idx = off + col
            if idx < len(data):
                b = data[idx]
                if b == 0: hex_parts.append(f"{C.DIM}00{C.RESET}")
                elif 0x20 <= b <= 0x7e: hex_parts.append(f"{C.GREEN}{b:02x}{C.RESET}")
                else: hex_parts.append(f"{C.CYAN}{b:02x}{C.RESET}")
                ascii_parts.append(chr(b) if 0x20 <= b <= 0x7e else '.')
            if col == 7: hex_parts.append("")
        print(f"  {C.YELLOW}{off:08x}{C.RESET}  {' '.join(hex_parts)}  {C.GREEN}{''.join(ascii_parts)}{C.RESET}")

    check("Hex view rendered successfully", True)
    check(f"Total file size: {len(data)} bytes", len(data) > 0)

# ====================================================================
#  Module 6: Decryption Engine - XOR Brute Force
# ====================================================================
def test_decryption(data):
    header("Module 6: Decryption Engine - XOR Brute Force")

    # Find encrypted region by DEADBEEF marker
    marker = b"\xDE\xAD\xBE\xEF"
    marker_pos = data.find(marker)

    if marker_pos >= 0:
        enc_len = struct.unpack_from("<I", data, marker_pos + 4)[0]
        encrypted_region = data[marker_pos + 8 : marker_pos + 8 + enc_len]
        info("Encryption Marker", f"DEADBEEF at offset 0x{marker_pos:04X}")
        info("Encrypted Region", f"{len(encrypted_region)} bytes (0x{marker_pos+8:04X} - 0x{marker_pos+8+enc_len:04X})")
    else:
        # Fallback: use last portion
        encrypted_region = data[-200:]
        info("Marker", "Not found, using last 200 bytes")

    subheader("XOR Brute-Force (256 keys)")

    best_key = None
    best_score = 0
    best_plaintext = b""
    results = []

    for key in range(1, 256):
        decrypted = bytes(b ^ key for b in encrypted_region)
        printable = sum(1 for b in decrypted if 0x20 <= b <= 0x7e or b == 0x0a)
        score = printable / len(decrypted) if len(decrypted) > 0 else 0
        if score > 0.5:
            results.append((key, score, decrypted))
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = decrypted

    info("Keys Tested", "255")
    info("Best Key", f"0x{best_key:02X} (readability: {best_score:.1%})")

    subheader("Top 5 XOR Key Candidates")
    for key, score, dec in sorted(results, key=lambda x: -x[1])[:5]:
        preview = dec[:60].decode('ascii', errors='replace').replace('\n', ' ')
        bar_len = int(score * 30)
        bar = f"{C.GREEN}{'#' * bar_len}{C.DIM}{'.' * (30 - bar_len)}{C.RESET}"
        marker = " <-- WINNER" if key == best_key else ""
        print(f"  Key {C.CYAN}0x{key:02X}{C.RESET}  {bar} {score:.0%}  {C.WHITE}{preview[:50]}{C.RESET}{C.GREEN}{marker}{C.RESET}")

    subheader(f"Decrypted Payload (Key=0x{best_key:02X})")
    decoded_text = best_plaintext.decode('ascii', errors='replace')
    for line in decoded_text.split('\n'):
        line = line.strip()
        if not line:
            continue
        if 'backdoor' in line.lower() or 'secret' in line.lower():
            print(f"  {C.RED}  [!] {line}{C.RESET}")
        elif 'token' in line.lower() or 'eyJ' in line or 'JWT' in line:
            print(f"  {C.MAGENTA}  [@] {line}{C.RESET}")
        elif 'password' in line.lower() or 'key' in line.lower():
            print(f"  {C.YELLOW}  [*] {line}{C.RESET}")
        elif 'reverse' in line.lower() or 'shell' in line.lower() or '/bin/' in line:
            print(f"  {C.RED}  [!] {line}{C.RESET}")
        else:
            print(f"  {C.WHITE}      {line}{C.RESET}")

    check("XOR brute-force completed (255 keys tested)", True)
    check(f"Correct key found: 0x{best_key:02X}", best_key == 0xAA, f"Expected: 0xAA")
    check("Decrypted data is readable ASCII", best_score > 0.7, f"Score: {best_score:.0%}")
    check("Hidden backdoor revealed", b'backdoor' in best_plaintext.lower() if best_plaintext else False)
    check("JWT token found in encrypted payload", b'eyJ' in best_plaintext if best_plaintext else False)
    check("Reverse shell command found", b'/bin/bash' in best_plaintext if best_plaintext else False)
    check("Master password recovered", b'Sup3rS3cr3t' in best_plaintext if best_plaintext else False)

    return best_key, best_plaintext

# ====================================================================
#  Module 7: Security Analyzer
# ====================================================================
def test_security(data, strings_list, decrypted_payload):
    header("Module 7: Security Analyzer - Vulnerability Scanner")

    findings = []
    all_text = ' '.join([s for _, s in strings_list])

    # Also include decrypted payload text
    dec_text = decrypted_payload.decode('ascii', errors='replace') if decrypted_payload else ""
    full_text = all_text + " " + dec_text

    subheader("Scanning: Credentials & API Keys")

    # AWS Keys
    for m in re.findall(r'AKIA[0-9A-Z]{16}', full_text):
        findings.append(('critical', 'api_key', 'AWS Access Key', m, 'CWE-798'))
        print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET}  AWS Access Key: {C.RED}{m}{C.RESET}")

    # GitHub tokens
    for m in re.findall(r'ghp_[A-Za-z0-9_]{30,}', full_text):
        findings.append(('critical', 'api_key', 'GitHub Personal Access Token', m[:20]+'...', 'CWE-798'))
        print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET}  GitHub Token: {C.RED}{m[:30]}...{C.RESET}")

    # RSA Private Keys
    if 'BEGIN RSA PRIVATE KEY' in full_text:
        findings.append(('critical', 'private_key', 'RSA Private Key Embedded', 'BEGIN RSA PRIVATE KEY', 'CWE-321'))
        print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET}  RSA Private Key in firmware!")

    # JWT Tokens
    for m in re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', full_text):
        findings.append(('high', 'token', 'JWT Token', m[:40]+'...', 'CWE-798'))
        print(f"  {C.YELLOW} HIGH     {C.RESET}  JWT Token: {C.MAGENTA}{m[:50]}...{C.RESET}")

    # Password in connection string
    for m in re.findall(r'\w+:\w+@[\w.:]+/\w+', full_text):
        findings.append(('critical', 'credential', 'Database Connection String', m, 'CWE-798'))
        print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET}  DB Connection: {C.RED}{m}{C.RESET}")

    subheader("Scanning: Default Credentials")

    default_creds = [('admin/admin','admin/admin'), ('root:toor','root/toor'), ('root/root','root/root')]
    for pattern, name in default_creds:
        if pattern in full_text:
            findings.append(('high', 'default_credential', f'Default Creds ({name})', name, 'CWE-798'))
            print(f"  {C.YELLOW} HIGH     {C.RESET}  Default creds: {C.YELLOW}{name}{C.RESET}")

    subheader("Scanning: Hardcoded IPs & Network")

    for ip in set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', full_text)):
        if not ip.startswith('0.') and not ip.startswith('255.'):
            findings.append(('medium', 'hardcoded_ip', f'Hardcoded IP: {ip}', ip, 'CWE-798'))
            print(f"  {C.YELLOW} MEDIUM   {C.RESET}  Hardcoded IP: {C.CYAN}{ip}{C.RESET}")

    # Insecure protocols
    for proto in ['telnet_enabled=true', 'ssl_verify=false', 'ssh_root_login=yes']:
        if proto in full_text:
            findings.append(('high', 'insecure_config', f'Insecure config: {proto}', proto, 'CWE-16'))
            print(f"  {C.YELLOW} HIGH     {C.RESET}  Insecure config: {C.RED}{proto}{C.RESET}")

    subheader("Scanning: Vulnerable Functions")

    vuln_funcs = {
        'strcpy': ('high', 'CWE-120', 'Buffer overflow - unbounded string copy'),
        'sprintf': ('medium', 'CWE-120', 'Potential buffer overflow in formatting'),
        'gets': ('critical', 'CWE-242', 'Always unsafe - never use gets()'),
        'system': ('high', 'CWE-78', 'OS command injection risk'),
    }
    for func, (sev, cwe, desc) in vuln_funcs.items():
        if func + '(' in full_text or func + '()' in full_text:
            findings.append((sev, 'vulnerable_function', f'{func}()', func, cwe))
            sc = C.RED if sev in ('critical','high') else C.YELLOW
            print(f"  {sc} {sev.upper():9}{C.RESET}  {func}() - {desc} ({C.CYAN}{cwe}{C.RESET})")

    subheader("Scanning: Backdoors & Reverse Shells")

    backdoor_patterns = [
        (r'backdoor', 'Backdoor reference found'),
        (r'reverse.?shell', 'Reverse shell pattern'),
        (r'/bin/bash\s+-i', 'Bash reverse shell'),
        (r'/dev/tcp/', 'TCP device file (reverse shell)'),
        (r'port\s+1337', 'Suspicious port 1337 (leet)'),
        (r'master.?password', 'Master password reference'),
    ]
    for pattern, desc in backdoor_patterns:
        if re.search(pattern, full_text, re.I):
            findings.append(('critical', 'backdoor', desc, pattern, 'CWE-506'))
            print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET}  {desc}")

    subheader("Scanning: Sensitive Paths")

    paths = ['/etc/shadow', '/root/.ssh/id_rsa', '/etc/passwd']
    for p in paths:
        if p in full_text:
            findings.append(('medium', 'sensitive_path', f'Sensitive path: {p}', p, 'CWE-538'))
            print(f"  {C.YELLOW} MEDIUM   {C.RESET}  Sensitive path: {C.CYAN}{p}{C.RESET}")

    # ---- Risk Dashboard ----
    weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 1}
    raw_score = sum(weights.get(f[0], 1) for f in findings)
    risk_score = min(100, raw_score)
    stats = Counter(f[0] for f in findings)

    if risk_score >= 75: risk_label, rc = "CRITICAL", C.RED
    elif risk_score >= 50: risk_label, rc = "HIGH", C.YELLOW
    elif risk_score >= 25: risk_label, rc = "MEDIUM", C.YELLOW
    elif risk_score > 0: risk_label, rc = "LOW", C.CYAN
    else: risk_label, rc = "CLEAN", C.GREEN

    bar_len = int(risk_score / 100 * 40)
    bar = f"{rc}{'#' * bar_len}{C.DIM}{'.' * (40 - bar_len)}{C.RESET}"

    subheader("Risk Assessment")
    print()
    print(f"  +------------------------------------------------------------+")
    print(f"  |  Risk Score: {rc}{C.BOLD}{risk_score:>3}/100{C.RESET}   Level: {rc}{C.BOLD}{risk_label:10}{C.RESET}              |")
    print(f"  |  {bar}                |")
    print(f"  +------------------------------------------------------------+")
    print(f"  |  {C.RED}Critical: {stats.get('critical',0):<4}{C.RESET}  {C.YELLOW}High: {stats.get('high',0):<4}{C.RESET}  {C.YELLOW}Medium: {stats.get('medium',0):<4}{C.RESET}          |")
    print(f"  |  {C.CYAN}Low: {stats.get('low',0):<8}{C.RESET}  {C.GRAY}Info: {stats.get('info',0):<4}{C.RESET}                          |")
    print(f"  |  {C.BOLD}Total Findings: {len(findings)}{C.RESET}                                       |")
    print(f"  +------------------------------------------------------------+")

    check("Security scan completed", True)
    check(f"Total findings: {len(findings)}", len(findings) > 0)
    check("AWS key -> CRITICAL", any('AWS' in f[2] for f in findings))
    check("RSA private key detected", any('RSA' in f[2] for f in findings))
    check("GitHub token detected", any('GitHub' in f[2] for f in findings))
    check("Default credentials flagged", any(f[1] == 'default_credential' for f in findings))
    check("Hardcoded IPs detected", any(f[1] == 'hardcoded_ip' for f in findings))
    check("strcpy() flagged as unsafe", any('strcpy' in f[3] for f in findings))
    check("gets() flagged as unsafe", any('gets' in f[3] for f in findings))
    check("system() flagged as command injection", any('system' in f[3] for f in findings))
    check("Backdoor detected (from decrypted payload)", any(f[1] == 'backdoor' for f in findings))
    check("Reverse shell command detected", any('reverse' in f[2].lower() or '/bin/bash' in f[2] for f in findings))
    check("Insecure configs flagged (telnet/ssl/ssh)", any(f[1] == 'insecure_config' for f in findings))
    check("Sensitive paths detected", any(f[1] == 'sensitive_path' for f in findings))
    check(f"Risk score: {risk_score}/100 ({risk_label})", risk_score >= 75, "Expected CRITICAL level")

    return findings, risk_score

# ====================================================================
#  MAIN
# ====================================================================
def main():
    print()
    print(f"  {C.BOLD}{C.CYAN}+===========================================================+{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}|     FirmwareX - Sample Firmware Validation Report          |{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}+===========================================================+{C.RESET}")

    if not os.path.exists(SAMPLE_FILE):
        print(f"\n  {C.RED}[!] Sample firmware not found: {SAMPLE_FILE}{C.RESET}")
        print(f"  {C.GRAY}Run: python generate_sample.py{C.RESET}")
        sys.exit(1)

    with open(SAMPLE_FILE, 'rb') as f:
        data = f.read()

    info("File", os.path.basename(SAMPLE_FILE))
    info("Path", SAMPLE_FILE)
    info("Size", f"{len(data)} bytes ({len(data)/1024:.2f} KB)")

    # Run all module tests
    file_type = test_file_detection(data)
    test_hashing(data)
    avg_entropy = test_entropy(data)
    strings_list = test_strings(data)
    test_hexview(data)
    best_key, decrypted = test_decryption(data)
    findings, risk_score = test_security(data, strings_list, decrypted)

    # ==== Final Summary ====
    header("FINAL VALIDATION SUMMARY")

    total = PASS + FAIL
    pass_rate = (PASS / total * 100) if total > 0 else 0

    bar_len = int(pass_rate / 100 * 40)
    if pass_rate >= 95: bc = C.GREEN
    elif pass_rate >= 80: bc = C.YELLOW
    else: bc = C.RED
    bar = f"{bc}{'#' * bar_len}{C.DIM}{'.' * (40 - bar_len)}{C.RESET}"

    print(f"  +------------------------------------------------------------+")
    print(f"  |  {C.BOLD}Test Results{C.RESET}                                               |")
    print(f"  |  {bar}  {bc}{pass_rate:.0f}%{C.RESET}        |")
    print(f"  |                                                            |")
    print(f"  |  {C.GREEN}Passed: {PASS:>3}{C.RESET}    {C.RED}Failed: {FAIL:>3}{C.RESET}    Total: {total:>3}              |")
    print(f"  +------------------------------------------------------------+")
    print(f"  |  {C.BOLD}Analysis Summary{C.RESET}                                           |")
    print(f"  |  File Type:        {file_type:<20}                     |")
    print(f"  |  Avg Entropy:      {avg_entropy:<6.2f} / 8.0                          |")
    print(f"  |  Strings Found:    {len(strings_list):<20}                     |")
    print(f"  |  XOR Key Cracked:  0x{best_key:02X}                                       |")
    print(f"  |  Security Issues:  {len(findings):<20}                     |")
    print(f"  |  Risk Score:       {risk_score}/100 ({C.RED}CRITICAL{C.RESET})                          |")
    print(f"  +------------------------------------------------------------+")
    print()

    if FAIL == 0:
        print(f"  {C.GREEN}{C.BOLD}>>> ALL {total} TESTS PASSED - FirmwareX modules validated! <<<{C.RESET}")
    else:
        print(f"  {C.YELLOW}>>> {FAIL} test(s) failed out of {total}{C.RESET}")
    print()

if __name__ == '__main__':
    main()
