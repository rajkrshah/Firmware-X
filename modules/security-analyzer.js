(function(root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.SecurityAnalyzer = factory();
    }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : global), function() {
    'use strict';

    // ── Severity Levels ─────────────────────────────────────
    const SEVERITY = {
        CRITICAL: 'critical',
        HIGH: 'high',
        MEDIUM: 'medium',
        LOW: 'low',
        INFO: 'info'
    };

    // ── Finding Categories ──────────────────────────────────
    const CATEGORY = {
        CREDENTIAL: 'credential',
        PRIVATE_KEY: 'private_key',
        CERTIFICATE: 'certificate',
        API_KEY: 'api_key',
        TOKEN: 'token',
        SECRET: 'secret',
        BACKDOOR: 'backdoor',
        VULN_FUNCTION: 'vulnerable_function',
        WEAK_CRYPTO: 'weak_crypto',
        DEBUG_INFO: 'debug_info',
        NETWORK: 'network',
        HARDCODED_IP: 'hardcoded_ip',
        SENSITIVE_PATH: 'sensitive_path',
        SENSITIVE_CONFIG: 'sensitive_config',
        DEFAULT_CRED: 'default_credential',
        INSECURE_PROTOCOL: 'insecure_protocol',
        COMMAND_INJECTION: 'command_injection',
        BUFFER_OVERFLOW: 'buffer_overflow',
        FORMAT_STRING: 'format_string',
        INFO_LEAK: 'info_leak'
    };

    // ── Category to Default CWE Mapping ─────────────────────
    const CATEGORY_CWE = {
        [CATEGORY.CREDENTIAL]: 'CWE-798',
        [CATEGORY.PRIVATE_KEY]: 'CWE-320',
        [CATEGORY.CERTIFICATE]: 'CWE-295',
        [CATEGORY.API_KEY]: 'CWE-798',
        [CATEGORY.TOKEN]: 'CWE-798',
        [CATEGORY.SECRET]: 'CWE-798',
        [CATEGORY.BACKDOOR]: 'CWE-506',
        [CATEGORY.WEAK_CRYPTO]: 'CWE-327',
        [CATEGORY.DEBUG_INFO]: 'CWE-489',
        [CATEGORY.HARDCODED_IP]: 'CWE-200',
        [CATEGORY.SENSITIVE_PATH]: 'CWE-200',
        [CATEGORY.SENSITIVE_CONFIG]: 'CWE-200',
        [CATEGORY.DEFAULT_CRED]: 'CWE-798',
        [CATEGORY.INSECURE_PROTOCOL]: 'CWE-319',
        [CATEGORY.COMMAND_INJECTION]: 'CWE-78',
        [CATEGORY.BUFFER_OVERFLOW]: 'CWE-120',
        [CATEGORY.FORMAT_STRING]: 'CWE-134',
        [CATEGORY.INFO_LEAK]: 'CWE-200'
    };

    // ── Pattern Databases ───────────────────────────────────

    /**
     * Private key / certificate patterns (regex on strings)
     */
    const KEY_PATTERNS = [
        { pattern: /-----BEGIN RSA PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'RSA Private Key', description: 'Embedded RSA private key found — can be used to impersonate the device or decrypt communications' },
        { pattern: /-----BEGIN EC PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'EC Private Key', description: 'Embedded Elliptic Curve private key' },
        { pattern: /-----BEGIN DSA PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'DSA Private Key', description: 'Embedded DSA private key' },
        { pattern: /-----BEGIN PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'PKCS#8 Private Key', description: 'Embedded PKCS#8 private key' },
        { pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.HIGH, name: 'Encrypted Private Key', description: 'Encrypted private key — passphrase may be nearby in firmware' },
        { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'OpenSSH Private Key', description: 'Embedded OpenSSH private key — SSH access possible' },
        { pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'PGP Private Key', description: 'Embedded PGP/GPG private key' },
        { pattern: /-----BEGIN CERTIFICATE-----/i, category: CATEGORY.CERTIFICATE, severity: SEVERITY.MEDIUM, name: 'X.509 Certificate', description: 'Embedded certificate — check validity and issuer' },
        { pattern: /-----BEGIN X509 CRL-----/i, category: CATEGORY.CERTIFICATE, severity: SEVERITY.LOW, name: 'Certificate Revocation List', description: 'Certificate revocation list found' },
        { pattern: /-----BEGIN PUBLIC KEY-----/i, category: CATEGORY.CERTIFICATE, severity: SEVERITY.INFO, name: 'Public Key', description: 'Embedded public key' },
        { pattern: /ssh-rsa\s+AAAA[A-Za-z0-9+\/=]+/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.MEDIUM, name: 'SSH Public Key', description: 'SSH public key — identify authorized keys' },
        { pattern: /ssh-ed25519\s+AAAA[A-Za-z0-9+\/=]+/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.MEDIUM, name: 'SSH Ed25519 Key', description: 'SSH Ed25519 public key' },
    ];

    /**
     * API key and token patterns
     */
    const API_KEY_PATTERNS = [
        { pattern: /AIza[0-9A-Za-z\-_]{35}/, category: CATEGORY.API_KEY, severity: SEVERITY.CRITICAL, name: 'Google API Key', description: 'Hardcoded Google API key' },
        { pattern: /AKIA[0-9A-Z]{16}/, category: CATEGORY.API_KEY, severity: SEVERITY.CRITICAL, name: 'AWS Access Key ID', description: 'Hardcoded AWS access key — full cloud access possible' },
        { pattern: /[0-9a-f]{40}/, category: CATEGORY.API_KEY, severity: SEVERITY.LOW, name: 'Potential SHA1 Hash/Token', description: '40-char hex string — could be API token or hash', maxFindings: 5 },
        { pattern: /ghp_[A-Za-z0-9]{36}/, category: CATEGORY.TOKEN, severity: SEVERITY.CRITICAL, name: 'GitHub Personal Access Token', description: 'Hardcoded GitHub PAT' },
        { pattern: /glpat-[A-Za-z0-9\-]{20}/, category: CATEGORY.TOKEN, severity: SEVERITY.CRITICAL, name: 'GitLab Personal Access Token', description: 'Hardcoded GitLab PAT' },
        { pattern: /sk-[A-Za-z0-9]{48}/, category: CATEGORY.API_KEY, severity: SEVERITY.CRITICAL, name: 'OpenAI API Key', description: 'Hardcoded OpenAI API key' },
        { pattern: /xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/, category: CATEGORY.TOKEN, severity: SEVERITY.CRITICAL, name: 'Slack Token', description: 'Hardcoded Slack bot/user token' },
        { pattern: /sk_live_[0-9a-zA-Z]{24}/, category: CATEGORY.API_KEY, severity: SEVERITY.CRITICAL, name: 'Stripe Secret Key', description: 'Hardcoded Stripe live secret key' },
        { pattern: /sq0atp-[0-9A-Za-z\-_]{22}/, category: CATEGORY.API_KEY, severity: SEVERITY.CRITICAL, name: 'Square Access Token', description: 'Hardcoded Square OAuth token' },
        { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, category: CATEGORY.TOKEN, severity: SEVERITY.HIGH, name: 'JSON Web Token (JWT)', description: 'Hardcoded JWT — may contain sensitive claims', maxFindings: 3 },
        { pattern: /bearer\s+[A-Za-z0-9\-._~+\/]+=*/i, category: CATEGORY.TOKEN, severity: SEVERITY.HIGH, name: 'Bearer Token', description: 'Hardcoded bearer authentication token' },
    ];

    /**
     * Credential patterns (matched against strings)
     */
    const CREDENTIAL_PATTERNS = [
        { pattern: /password\s*[=:]\s*["']?([^\s"']{3,})/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.CRITICAL, name: 'Hardcoded Password', description: 'Password value found in plaintext' },
        { pattern: /passwd\s*[=:]\s*["']?([^\s"']{3,})/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.CRITICAL, name: 'Hardcoded Password (passwd)', description: 'Password value found' },
        { pattern: /pwd\s*[=:]\s*["']?([^\s"']{3,})/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.HIGH, name: 'Hardcoded Password (pwd)', description: 'Possible password assignment' },
        { pattern: /secret\s*[=:]\s*["']?([^\s"']{3,})/i, category: CATEGORY.SECRET, severity: SEVERITY.HIGH, name: 'Hardcoded Secret', description: 'Secret value found in plaintext' },
        { pattern: /api[_-]?key\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.API_KEY, severity: SEVERITY.HIGH, name: 'Hardcoded API Key', description: 'API key value found in plaintext' },
        { pattern: /api[_-]?secret\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.SECRET, severity: SEVERITY.CRITICAL, name: 'Hardcoded API Secret', description: 'API secret value found' },
        { pattern: /auth[_-]?token\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.TOKEN, severity: SEVERITY.HIGH, name: 'Hardcoded Auth Token', description: 'Authentication token found' },
        { pattern: /access[_-]?token\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.TOKEN, severity: SEVERITY.HIGH, name: 'Hardcoded Access Token', description: 'Access token found' },
        { pattern: /private[_-]?key\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.PRIVATE_KEY, severity: SEVERITY.CRITICAL, name: 'Hardcoded Private Key Value', description: 'Private key value in plaintext' },
        { pattern: /encryption[_-]?key\s*[=:]\s*["']?([^\s"']{8,})/i, category: CATEGORY.SECRET, severity: SEVERITY.CRITICAL, name: 'Hardcoded Encryption Key', description: 'Encryption key found in plaintext' },
        { pattern: /master[_-]?key\s*[=:]\s*["']?([^\s"']{4,})/i, category: CATEGORY.SECRET, severity: SEVERITY.CRITICAL, name: 'Hardcoded Master Key', description: 'Master key found' },
        { pattern: /root:[^:]*:[0-9]+:[0-9]+:/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.HIGH, name: 'Unix passwd Entry (root)', description: 'Root user passwd entry — check for password hash' },
        { pattern: /admin:[^:]*:[0-9]+:[0-9]+:/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.MEDIUM, name: 'Unix passwd Entry (admin)', description: 'Admin user passwd entry' },
        { pattern: /\$1\$[a-zA-Z0-9.\/]{8}\$[a-zA-Z0-9.\/]{22}/, category: CATEGORY.CREDENTIAL, severity: SEVERITY.HIGH, name: 'MD5 Password Hash ($1$)', description: 'MD5-crypt password hash — weak, crackable' },
        { pattern: /\$5\$[a-zA-Z0-9.\/]{8,16}\$[a-zA-Z0-9.\/]{43}/, category: CATEGORY.CREDENTIAL, severity: SEVERITY.MEDIUM, name: 'SHA-256 Password Hash ($5$)', description: 'SHA-256 crypt password hash' },
        { pattern: /\$6\$[a-zA-Z0-9.\/]{8,16}\$[a-zA-Z0-9.\/]{86}/, category: CATEGORY.CREDENTIAL, severity: SEVERITY.MEDIUM, name: 'SHA-512 Password Hash ($6$)', description: 'SHA-512 crypt password hash' },
        { pattern: /\$2[aby]?\$[0-9]{2}\$[A-Za-z0-9.\/]{53}/, category: CATEGORY.CREDENTIAL, severity: SEVERITY.MEDIUM, name: 'Bcrypt Password Hash ($2$)', description: 'Bcrypt password hash' },
    ];

    /**
     * Default / well-known credentials
     */
    const DEFAULT_CREDENTIALS = [
        { user: 'admin', pass: 'admin', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: 'password', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: '1234', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: '12345', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: '123456', severity: SEVERITY.CRITICAL },
        { user: 'root', pass: 'root', severity: SEVERITY.CRITICAL },
        { user: 'root', pass: 'toor', severity: SEVERITY.CRITICAL },
        { user: 'root', pass: 'password', severity: SEVERITY.CRITICAL },
        { user: 'root', pass: '', severity: SEVERITY.CRITICAL },
        { user: 'user', pass: 'user', severity: SEVERITY.HIGH },
        { user: 'guest', pass: 'guest', severity: SEVERITY.HIGH },
        { user: 'test', pass: 'test', severity: SEVERITY.MEDIUM },
        { user: 'admin', pass: 'default', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: 'admin123', severity: SEVERITY.CRITICAL },
        { user: 'supervisor', pass: 'supervisor', severity: SEVERITY.CRITICAL },
        { user: 'support', pass: 'support', severity: SEVERITY.HIGH },
        { user: 'debug', pass: 'debug', severity: SEVERITY.HIGH },
        { user: 'service', pass: 'service', severity: SEVERITY.HIGH },
        { user: 'daemon', pass: 'daemon', severity: SEVERITY.MEDIUM },
        { user: 'ubnt', pass: 'ubnt', severity: SEVERITY.CRITICAL },
        { user: 'pi', pass: 'raspberry', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: 'changeme', severity: SEVERITY.CRITICAL },
        { user: 'admin', pass: 'pass', severity: SEVERITY.CRITICAL },
    ];

    /**
     * Vulnerable / dangerous C functions
     */
    const VULN_FUNCTIONS = [
        { name: 'strcpy', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.HIGH, description: 'Unbounded string copy — classic buffer overflow vector. Use strncpy or strlcpy instead.', cwe: 'CWE-120' },
        { name: 'strcat', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.HIGH, description: 'Unbounded string concatenation — buffer overflow risk. Use strncat or strlcat.', cwe: 'CWE-120' },
        { name: 'sprintf', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.HIGH, description: 'Unbounded formatted print to buffer — use snprintf instead.', cwe: 'CWE-120' },
        { name: 'vsprintf', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.HIGH, description: 'Unbounded variadic formatted print — use vsnprintf instead.', cwe: 'CWE-120' },
        { name: 'gets', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.CRITICAL, description: 'Reads unlimited input — guaranteed buffer overflow. Removed in C11. Use fgets.', cwe: 'CWE-242' },
        { name: 'scanf', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.MEDIUM, description: 'Can overflow buffer without width specifier. Use width-limited format.', cwe: 'CWE-120' },
        { name: 'sscanf', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.MEDIUM, description: 'Can overflow without width specifier.', cwe: 'CWE-120' },
        { name: 'realpath', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.MEDIUM, description: 'Can overflow if resolved path exceeds PATH_MAX.', cwe: 'CWE-120' },
        { name: 'getwd', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.MEDIUM, description: 'Deprecated — buffer size not checked. Use getcwd.', cwe: 'CWE-120' },
        { name: 'mktemp', category: CATEGORY.VULN_FUNCTION, severity: SEVERITY.MEDIUM, description: 'Race condition in temp file creation. Use mkstemp.', cwe: 'CWE-377' },
        { name: 'system', category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.HIGH, description: 'Executes shell command — command injection risk if input not sanitized.', cwe: 'CWE-78' },
        { name: 'popen', category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.HIGH, description: 'Executes shell command via pipe — injection risk.', cwe: 'CWE-78' },
        { name: 'execve', category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.MEDIUM, description: 'Direct process execution — verify arguments are sanitized.', cwe: 'CWE-78' },
        { name: 'execl', category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.MEDIUM, description: 'Direct process execution.', cwe: 'CWE-78' },
        { name: 'execlp', category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.MEDIUM, description: 'Process execution with PATH search.', cwe: 'CWE-78' },
        { name: 'printf', category: CATEGORY.FORMAT_STRING, severity: SEVERITY.MEDIUM, description: 'Format string vulnerability if user input is passed as format. Use printf("%s", var).', cwe: 'CWE-134' },
        { name: 'fprintf', category: CATEGORY.FORMAT_STRING, severity: SEVERITY.MEDIUM, description: 'Format string attack vector if format controlled by user.', cwe: 'CWE-134' },
        { name: 'syslog', category: CATEGORY.FORMAT_STRING, severity: SEVERITY.MEDIUM, description: 'Format string vulnerability in syslog if user data used as format.', cwe: 'CWE-134' },
        { name: 'alloca', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.MEDIUM, description: 'Stack allocation without size check — stack overflow risk.', cwe: 'CWE-770' },
        { name: 'memcpy', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.LOW, description: 'Unbounded memory copy — ensure size is validated.', cwe: 'CWE-120' },
        { name: 'memmove', category: CATEGORY.BUFFER_OVERFLOW, severity: SEVERITY.LOW, description: 'Memory move without bounds check.', cwe: 'CWE-120' },
        { name: 'rand', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, description: 'Weak PRNG — predictable output. Use /dev/urandom or arc4random for crypto.', cwe: 'CWE-338' },
        { name: 'srand', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, description: 'Seeds weak PRNG — insecure for cryptographic use.', cwe: 'CWE-338' },
        { name: 'DES_ecb_encrypt', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, description: 'DES encryption — broken cipher, 56-bit key. Use AES instead.', cwe: 'CWE-327' },
        { name: 'MD5_Init', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, description: 'MD5 hash — collision attacks known. Use SHA-256+.', cwe: 'CWE-328' },
        { name: 'MD5_Update', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, description: 'MD5 in use — weak hash algorithm.', cwe: 'CWE-328' },
        { name: 'SHA1_Init', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, description: 'SHA-1 hash — collision attacks practical. Use SHA-256+.', cwe: 'CWE-328' },
        { name: 'EVP_des_ecb', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, description: 'DES in ECB mode — weak and deterministic.', cwe: 'CWE-327' },
        { name: 'EVP_des_cbc', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, description: 'DES in CBC mode — 56-bit key is breakable.', cwe: 'CWE-327' },
        { name: 'EVP_rc4', category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, description: 'RC4 cipher — known biases, prohibited by RFC 7465.', cwe: 'CWE-327' },
        { name: 'setuid', category: CATEGORY.VULN_FUNCTION, severity: SEVERITY.MEDIUM, description: 'Privilege escalation — verify proper drop of privileges.', cwe: 'CWE-250' },
        { name: 'setgid', category: CATEGORY.VULN_FUNCTION, severity: SEVERITY.MEDIUM, description: 'Group privilege change — verify intent.', cwe: 'CWE-250' },
        { name: 'chmod', category: CATEGORY.VULN_FUNCTION, severity: SEVERITY.LOW, description: 'Permission change — verify file and permission values.', cwe: 'CWE-732' },
        { name: 'chown', category: CATEGORY.VULN_FUNCTION, severity: SEVERITY.LOW, description: 'Ownership change — verify intent.', cwe: 'CWE-732' },
    ];

    /**
     * Insecure protocol / network patterns
     */
    const NETWORK_PATTERNS = [
        { pattern: /http:\/\/[^\s"'<>]{5,}/i, category: CATEGORY.INSECURE_PROTOCOL, severity: SEVERITY.MEDIUM, name: 'HTTP URL (Unencrypted)', description: 'Plaintext HTTP URL — data transmitted without encryption' },
        { pattern: /ftp:\/\/[^\s"'<>]{5,}/i, category: CATEGORY.INSECURE_PROTOCOL, severity: SEVERITY.HIGH, name: 'FTP URL (Unencrypted)', description: 'FTP URL — credentials and data in plaintext' },
        { pattern: /telnet:\/\/[^\s"'<>]{5,}/i, category: CATEGORY.INSECURE_PROTOCOL, severity: SEVERITY.CRITICAL, name: 'Telnet URL', description: 'Telnet — completely unencrypted remote access' },
        { pattern: /ftp:\/\/[^:]+:[^@]+@/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.CRITICAL, name: 'FTP URL with Credentials', description: 'FTP URL contains embedded username:password' },
        { pattern: /http:\/\/[^:]+:[^@]+@/i, category: CATEGORY.CREDENTIAL, severity: SEVERITY.CRITICAL, name: 'HTTP URL with Credentials', description: 'HTTP URL contains embedded credentials' },
        { pattern: /\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/, category: CATEGORY.HARDCODED_IP, severity: SEVERITY.LOW, name: 'Hardcoded IP Address', description: 'IP address found — check if it\'s a C2 server or update endpoint', maxFindings: 20 },
        { pattern: /[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}/i, category: CATEGORY.INFO_LEAK, severity: SEVERITY.LOW, name: 'MAC Address', description: 'MAC address found — device identification info', maxFindings: 10 },
    ];

    /**
     * Sensitive file paths
     */
    const SENSITIVE_PATHS = [
        { pattern: /\/etc\/shadow/i, severity: SEVERITY.CRITICAL, name: 'Shadow File Reference', description: 'Reference to /etc/shadow — password hashes storage' },
        { pattern: /\/etc\/passwd/i, severity: SEVERITY.MEDIUM, name: 'Passwd File Reference', description: 'Reference to /etc/passwd — user account info' },
        { pattern: /\/etc\/ssl\/private/i, severity: SEVERITY.HIGH, name: 'SSL Private Key Path', description: 'Reference to SSL private key directory' },
        { pattern: /\.pem\b/i, severity: SEVERITY.MEDIUM, name: 'PEM File Reference', description: 'PEM certificate/key file referenced' },
        { pattern: /\.key\b/i, severity: SEVERITY.MEDIUM, name: 'Key File Reference', description: 'Private key file referenced' },
        { pattern: /\.p12\b|\.pfx\b/i, severity: SEVERITY.HIGH, name: 'PKCS#12 File Reference', description: 'PKCS#12 keystore referenced — may contain private keys' },
        { pattern: /\.jks\b/i, severity: SEVERITY.HIGH, name: 'Java Keystore Reference', description: 'Java KeyStore referenced' },
        { pattern: /id_rsa|id_dsa|id_ecdsa|id_ed25519/i, severity: SEVERITY.CRITICAL, name: 'SSH Key File Reference', description: 'SSH private key file referenced' },
        { pattern: /authorized_keys/i, severity: SEVERITY.HIGH, name: 'SSH Authorized Keys', description: 'SSH authorized_keys file — backdoor SSH access possible' },
        { pattern: /\.env\b/i, severity: SEVERITY.HIGH, name: '.env File Reference', description: 'Environment file — often contains secrets' },
        { pattern: /wp-config\.php/i, severity: SEVERITY.HIGH, name: 'WordPress Config', description: 'WordPress config file — contains DB credentials' },
        { pattern: /\/dev\/kmem|\/dev\/mem/i, severity: SEVERITY.HIGH, name: 'Raw Memory Device', description: 'Direct memory access device — potential for memory dumping' },
        { pattern: /\/proc\/self/i, severity: SEVERITY.MEDIUM, name: 'Procfs Self Reference', description: 'Process introspection via procfs' },
        { pattern: /\/tmp\/|\/var\/tmp\//i, severity: SEVERITY.LOW, name: 'Temp Directory Usage', description: 'Temporary directory use — check for secure temp file creation', maxFindings: 5 },
    ];

    /**
     * Backdoor / suspicious patterns
     */
    const BACKDOOR_PATTERNS = [
        { pattern: /backdoor/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.CRITICAL, name: 'Backdoor Reference', description: 'String "backdoor" found in firmware' },
        { pattern: /debug[_-]?shell|debug[_-]?console|debug[_-]?mode/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.HIGH, name: 'Debug Shell/Console', description: 'Debug shell or console mechanism — potential unauthorized access' },
        { pattern: /master[_-]?password|skeleton[_-]?key|override[_-]?password/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.CRITICAL, name: 'Master/Skeleton Password', description: 'Master password or skeleton key mechanism detected' },
        { pattern: /hidden[_-]?user|secret[_-]?user|backdoor[_-]?user/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.CRITICAL, name: 'Hidden User Account', description: 'Hidden or secret user account mechanism' },
        { pattern: /reverse[_-]?shell|bind[_-]?shell|connect[_-]?back/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.CRITICAL, name: 'Reverse/Bind Shell', description: 'Shell connection mechanism — potential backdoor' },
        { pattern: /\/bin\/sh\s+-c|\/bin\/bash\s+-c|\/bin\/ash\s+-c/i, category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.MEDIUM, name: 'Shell Execution', description: 'Shell command execution — verify input sanitization' },
        { pattern: /nc\s+-[el]|netcat\s+-[el]|ncat\s+-[el]/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.HIGH, name: 'Netcat Listener', description: 'Netcat in listen mode — potential backdoor listener' },
        { pattern: /iptables\s+.*DROP|iptables\s+.*REJECT/i, category: CATEGORY.NETWORK, severity: SEVERITY.LOW, name: 'Firewall Rule', description: 'Firewall rules — check for overly permissive rules' },
        { pattern: /curl\s+.*\|\s*sh|wget\s+.*\|\s*sh/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.CRITICAL, name: 'Remote Code Execution', description: 'Download-and-execute pattern — remote code execution risk' },
        { pattern: /eval\s*\(|exec\s*\(/i, category: CATEGORY.COMMAND_INJECTION, severity: SEVERITY.MEDIUM, name: 'Dynamic Code Execution', description: 'Dynamic code evaluation — injection risk if input controlled' },
        { pattern: /ENABLE_TELNET|TELNETD_ENABLED|telnetd\s+-l/i, category: CATEGORY.BACKDOOR, severity: SEVERITY.HIGH, name: 'Telnet Daemon', description: 'Telnet daemon enabled — unencrypted remote access' },
    ];

    /**
     * Weak crypto configuration patterns
     */
    const CRYPTO_WEAKNESS_PATTERNS = [
        { pattern: /SSLv2|SSLv3|TLSv1\.0\b|TLSv1\.1\b/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, name: 'Deprecated TLS/SSL Version', description: 'Deprecated protocol version — vulnerable to POODLE, BEAST, etc.' },
        { pattern: /RC4|DES-CBC|DES-ECB|EXP-|NULL-/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, name: 'Weak Cipher Suite', description: 'Weak or broken cipher suite' },
        { pattern: /MD5WithRSA|md5WithRSAEncryption/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.HIGH, name: 'MD5 Signature Algorithm', description: 'MD5-based signature — collision attacks possible' },
        { pattern: /SHA1WithRSA|sha1WithRSAEncryption/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.MEDIUM, name: 'SHA-1 Signature Algorithm', description: 'SHA-1 signatures deprecated' },
        { pattern: /VERIFY_NONE|verify_mode\s*=\s*0|SSL_VERIFY_NONE/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.CRITICAL, name: 'TLS Verification Disabled', description: 'Certificate verification disabled — MITM attack possible' },
        { pattern: /AllowInsecure|InsecureSkipVerify|CURLOPT_SSL_VERIFYPEER.*0/i, category: CATEGORY.WEAK_CRYPTO, severity: SEVERITY.CRITICAL, name: 'SSL Verification Skip', description: 'SSL/TLS verification explicitly skipped' },
    ];

    // ══════════════════════════════════════════════════════
    //  SecurityAnalyzer Class
    // ══════════════════════════════════════════════════════

    function SecurityAnalyzer() {
        this.findings = [];
        this.stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    }

    /**
     * Run all security scans on the given data
     * @param {Uint8Array} uint8Array - Binary data to analyze
     * @param {Object} [options] - Analysis options
     * @param {number} [options.minStringLength=4] - Minimum string length for extraction
     * @param {boolean} [options.scanKeys=true] - Scan for private keys and certificates
     * @param {boolean} [options.scanCredentials=true] - Scan for hardcoded credentials
     * @param {boolean} [options.scanApiKeys=true] - Scan for API keys and tokens
     * @param {boolean} [options.scanVulnFunctions=true] - Scan for vulnerable functions
     * @param {boolean} [options.scanNetwork=true] - Scan for network/protocol issues
     * @param {boolean} [options.scanBackdoors=true] - Scan for backdoor patterns
     * @param {boolean} [options.scanCrypto=true] - Scan for weak crypto
     * @param {boolean} [options.scanDefaultCreds=true] - Scan for default credentials
     * @param {boolean} [options.scanPaths=true] - Scan for sensitive file paths
     * @returns {Object} Analysis results
     */
    SecurityAnalyzer.prototype.analyze = function(uint8Array, options) {
        options = Object.assign({
            minStringLength: 4,
            scanKeys: true,
            scanCredentials: true,
            scanApiKeys: true,
            scanVulnFunctions: true,
            scanNetwork: true,
            scanBackdoors: true,
            scanCrypto: true,
            scanDefaultCreds: true,
            scanPaths: true
        }, options || {});

        this.findings = [];
        this.stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

        // Extract strings first
        var strings = this._extractStrings(uint8Array, options.minStringLength);

        // Run scans
        if (options.scanKeys) this._scanPatterns(strings, KEY_PATTERNS);
        if (options.scanApiKeys) this._scanPatterns(strings, API_KEY_PATTERNS);
        if (options.scanCredentials) this._scanPatterns(strings, CREDENTIAL_PATTERNS);
        if (options.scanNetwork) this._scanPatterns(strings, NETWORK_PATTERNS);
        if (options.scanBackdoors) this._scanPatterns(strings, BACKDOOR_PATTERNS);
        if (options.scanCrypto) this._scanPatterns(strings, CRYPTO_WEAKNESS_PATTERNS);
        if (options.scanPaths) this._scanSensitivePaths(strings);
        if (options.scanVulnFunctions) this._scanVulnFunctions(strings);
        if (options.scanDefaultCreds) this._scanDefaultCredentials(strings);

        // Sort by severity
        var severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        this.findings.sort(function(a, b) {
            var orderA = severityOrder[a.severity] !== undefined ? severityOrder[a.severity] : 4;
            var orderB = severityOrder[b.severity] !== undefined ? severityOrder[b.severity] : 4;
            return orderA - orderB;
        });

        // Count stats
        this.stats.total = this.findings.length;
        for (var i = 0; i < this.findings.length; i++) {
            var sev = this.findings[i].severity;
            if (this.stats[sev] !== undefined) this.stats[sev]++;
        }

        return {
            findings: this.findings,
            stats: this.stats,
            summary: this._generateSummary(),
            riskScore: this._calculateRiskScore()
        };
    };

    /**
     * Extract printable strings from binary data
     * @private
     */
    SecurityAnalyzer.prototype._extractStrings = function(uint8Array, minLength) {
        var strings = [];
        var currentStr = '';
        var startOffset = 0;

        for (var i = 0; i < uint8Array.length; i++) {
            var byte = uint8Array[i];
            if (byte >= 32 && byte <= 126) {
                if (currentStr.length === 0) startOffset = i;
                currentStr += String.fromCharCode(byte);
            } else {
                if (currentStr.length >= minLength) {
                    strings.push({
                        offset: startOffset,
                        string: currentStr,
                        length: currentStr.length
                    });
                }
                currentStr = '';
            }
        }
        if (currentStr.length >= minLength) {
            strings.push({
                offset: startOffset,
                string: currentStr,
                length: currentStr.length
            });
        }
        return strings;
    };

    /**
     * Scan strings against a pattern set
     * @private
     */
    SecurityAnalyzer.prototype._scanPatterns = function(strings, patterns) {
        for (var p = 0; p < patterns.length; p++) {
            var pat = patterns[p];
            var count = 0;
            var maxF = pat.maxFindings || 50;

            for (var s = 0; s < strings.length && count < maxF; s++) {
                var str = strings[s].string;
                var match = str.match(pat.pattern);
                if (match) {
                    this.findings.push({
                        category: pat.category,
                        severity: pat.severity,
                        name: pat.name,
                        description: pat.description,
                        cwe: pat.cwe || CATEGORY_CWE[pat.category] || null,
                        offset: strings[s].offset,
                        evidence: str.substring(0, 200),
                        matchedValue: match[0].substring(0, 100)
                    });
                    count++;
                }
            }
        }
    };

    /**
     * Scan for sensitive file paths
     * @private
     */
    SecurityAnalyzer.prototype._scanSensitivePaths = function(strings) {
        for (var p = 0; p < SENSITIVE_PATHS.length; p++) {
            var pat = SENSITIVE_PATHS[p];
            var count = 0;
            var maxF = pat.maxFindings || 10;

            for (var s = 0; s < strings.length && count < maxF; s++) {
                if (pat.pattern.test(strings[s].string)) {
                    this.findings.push({
                        category: CATEGORY.SENSITIVE_PATH,
                        severity: pat.severity,
                        name: pat.name,
                        description: pat.description,
                        offset: strings[s].offset,
                        evidence: strings[s].string.substring(0, 200),
                        matchedValue: strings[s].string.match(pat.pattern)[0]
                    });
                    count++;
                }
            }
        }
    };

    /**
     * Scan for vulnerable C/C++ functions in string table
     * @private
     */
    SecurityAnalyzer.prototype._scanVulnFunctions = function(strings) {
        for (var f = 0; f < VULN_FUNCTIONS.length; f++) {
            var func = VULN_FUNCTIONS[f];
            for (var s = 0; s < strings.length; s++) {
                var str = strings[s].string;
                // Match function name as a standalone symbol (common in ELF symbol tables)
                if (str === func.name || 
                    str === '_' + func.name || 
                    str.indexOf('@' + func.name) !== -1 ||
                    str.match(new RegExp('\\b' + func.name + '\\b'))) {
                    this.findings.push({
                        category: func.category || CATEGORY.VULN_FUNCTION,
                        severity: func.severity,
                        name: 'Unsafe Function: ' + func.name + '()',
                        description: func.description,
                        cwe: func.cwe,
                        offset: strings[s].offset,
                        evidence: str.substring(0, 100),
                        matchedValue: func.name
                    });
                    break; // Only report each function once
                }
            }
        }
    };

    /**
     * Scan for default credential combinations
     * @private
     */
    SecurityAnalyzer.prototype._scanDefaultCredentials = function(strings) {
        var allStrings = strings.map(function(s) { return s.string.toLowerCase(); });
        var allStringsSet = {};
        for (var i = 0; i < allStrings.length; i++) {
            allStringsSet[allStrings[i]] = strings[i].offset;
        }

        for (var d = 0; d < DEFAULT_CREDENTIALS.length; d++) {
            var cred = DEFAULT_CREDENTIALS[d];
            var userFound = false;
            var passFound = false;
            var userOffset = 0;

            for (var s = 0; s < strings.length; s++) {
                var lower = strings[s].string.toLowerCase();
                if (lower.indexOf(cred.user) !== -1) {
                    userFound = true;
                    userOffset = strings[s].offset;
                }
                if (cred.pass && lower.indexOf(cred.pass) !== -1) {
                    passFound = true;
                }
            }

            if (userFound && (passFound || !cred.pass)) {
                this.findings.push({
                    category: CATEGORY.DEFAULT_CRED,
                    severity: cred.severity,
                    name: 'Default Credential: ' + cred.user + '/' + (cred.pass || '(empty)'),
                    description: 'Both username "' + cred.user + '" and password "' + (cred.pass || '') + '" found in firmware — device may use default credentials',
                    offset: userOffset,
                    evidence: cred.user + ':' + (cred.pass || ''),
                    matchedValue: cred.user + '/' + (cred.pass || '')
                });
            }
        }
    };

    /**
     * Calculate overall risk score (0.0-10.0)
     * @private
     */
    SecurityAnalyzer.prototype._calculateRiskScore = function() {
        var score = 0.0;
        var cvssMap = { critical: 9.8, high: 7.5, medium: 5.5, low: 2.5, info: 0.0 };
        
        for (var i = 0; i < this.findings.length; i++) {
            var vulnScore = cvssMap[this.findings[i].severity] || 0.0;
            if (vulnScore > score) {
                score = vulnScore;
            }
        }

        return parseFloat(score.toFixed(1));
    };

    /**
     * Generate human-readable summary
     * @private
     */
    SecurityAnalyzer.prototype._generateSummary = function() {
        var riskScore = this._calculateRiskScore();
        var riskLevel;

        if (riskScore >= 9.0) riskLevel = 'CRITICAL';
        else if (riskScore >= 7.0) riskLevel = 'HIGH';
        else if (riskScore >= 4.0) riskLevel = 'MEDIUM';
        else if (riskScore >= 0.1) riskLevel = 'LOW';
        else riskLevel = 'CLEAN';

        return {
            riskLevel: riskLevel,
            riskScore: riskScore,
            totalFindings: this.findings.length,
            criticalCount: this.stats.critical,
            highCount: this.stats.high,
            mediumCount: this.stats.medium,
            lowCount: this.stats.low,
            infoCount: this.stats.info,
            topIssues: this.findings.slice(0, 5).map(function(f) {
                return f.name;
            }),
            categories: this._getCategoryBreakdown()
        };
    };

    /**
     * Get breakdown by category
     * @private
     */
    SecurityAnalyzer.prototype._getCategoryBreakdown = function() {
        var cats = {};
        for (var i = 0; i < this.findings.length; i++) {
            var cat = this.findings[i].category;
            cats[cat] = (cats[cat] || 0) + 1;
        }
        return cats;
    };

    /**
     * Get findings filtered by severity
     * @param {string} severity - 'critical', 'high', 'medium', 'low', 'info'
     * @returns {Array} Filtered findings
     */
    SecurityAnalyzer.prototype.getBySeverity = function(severity) {
        return this.findings.filter(function(f) { return f.severity === severity; });
    };

    /**
     * Get findings filtered by category
     * @param {string} category - Category constant
     * @returns {Array} Filtered findings
     */
    SecurityAnalyzer.prototype.getByCategory = function(category) {
        return this.findings.filter(function(f) { return f.category === category; });
    };

    /**
     * Format a single finding for CLI display
     * @param {Object} finding
     * @returns {Object} Formatted parts with color hints
     */
    SecurityAnalyzer.prototype.formatFinding = function(finding) {
        var sevIcon;
        switch (finding.severity) {
            case 'critical': sevIcon = '🔴'; break;
            case 'high':     sevIcon = '🟠'; break;
            case 'medium':   sevIcon = '🟡'; break;
            case 'low':      sevIcon = '🔵'; break;
            default:         sevIcon = '⚪'; break;
        }

        return {
            icon: sevIcon,
            severity: finding.severity.toUpperCase(),
            name: finding.name,
            description: finding.description,
            cwe: finding.cwe,
            offset: finding.offset !== undefined ? '0x' + finding.offset.toString(16).padStart(8, '0') : null,
            evidence: finding.evidence,
            matchedValue: finding.matchedValue,
            category: finding.category
        };
    };

    /**
     * Export constants for external use
     */
    SecurityAnalyzer.SEVERITY = SEVERITY;
    SecurityAnalyzer.CATEGORY = CATEGORY;

    return SecurityAnalyzer;
});
