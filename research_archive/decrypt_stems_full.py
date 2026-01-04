#!/usr/bin/env python3
"""
Full .stems file decryption using extracted XOR keys
"""

import struct
import re

print("[*] Engine DJ .stems Full Decryption")
print("=" * 80)

# Load all 10 extracted keys
keys_bytes = []
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

for match in re.finditer(r'Packet \d+.*?:((?:\s+[a-f0-9]{2})+)', content):
    hex_str = ''.join(match.group(1).split())
    keys_bytes.append(bytes.fromhex(hex_str))

print(f"[+] Loaded {len(keys_bytes)} XOR keys ({len(keys_bytes[0])} bytes each)")

# Read the encrypted .stems file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

print(f"[+] Read {len(stems_data)} bytes from {stems_file}")

# Parse MP4 structure to find mdat
pos = 0
mdat_offset = None
mdat_size = None

while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    
    if box_type == b'mdat':
        mdat_offset = pos + 8  # Skip 8-byte box header
        mdat_size = size - 8   # Size of payload only
        print(f"[+] Found mdat at offset 0x{pos:x}, payload at 0x{mdat_offset:x}")
        print(f"[+] Encrypted payload size: {mdat_size} bytes")
        break
    
    pos += size

if mdat_offset is None:
    print("[!] Could not find mdat box")
    exit(1)

# Extract encrypted payload
encrypted_payload = stems_data[mdat_offset:mdat_offset + mdat_size]
print(f"[+] Extracted encrypted payload: {len(encrypted_payload)} bytes")

# Decrypt using cyclic key pattern
print(f"[*] Decrypting payload...")
decrypted_payload = bytearray()

key_size = len(keys_bytes[0])
total_bytes_decrypted = 0

# Strategy: We have 10 keys, each 128 bytes
# The encrypted data is likely 1024 bytes per frame (AAC packets)
# So keys might repeat cyclically or apply per frame

# First, let's just try repeating all 10 keys cyclically
keys_combined = b''.join(keys_bytes)  # 10 * 128 = 1280 bytes
print(f"[*] Combined key length: {len(keys_combined)} bytes")
print(f"[*] Repeating keys cyclically through {len(encrypted_payload)} bytes...")

for i, encrypted_byte in enumerate(encrypted_payload):
    key_byte = keys_combined[i % len(keys_combined)]
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_payload.append(decrypted_byte)
    total_bytes_decrypted += 1
    
    if (i + 1) % 100000 == 0:
        print(f"    [{i+1}/{len(encrypted_payload)}] {100*(i+1)/len(encrypted_payload):.1f}%")

print(f"[+] Decrypted {total_bytes_decrypted} bytes")

# Verify decryption by checking for audio signatures
# Look for ADTS sync word (0xFF 0xF?) or Lavc signature
first_128 = decrypted_payload[:128]
print(f"\n[*] Verification - first 128 bytes (hex):")
print(f"    {' '.join(f'{b:02x}' for b in first_128[:64])}")
print(f"    {' '.join(f'{b:02x}' for b in first_128[64:])}")

print(f"\n[*] Verification - first 64 bytes (ASCII):")
ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in first_128[:64])
print(f"    {ascii_part}")

if b'Lavc' in bytes(decrypted_payload[:256]):
    print(f"\n[+] Found FFmpeg 'Lavc' signature - decryption appears correct!")
elif decrypted_payload[0] == 0xFF and (decrypted_payload[1] & 0xF0) == 0xF0:
    print(f"\n[+] Found ADTS sync word - decryption appears correct!")
else:
    print(f"\n[?] No known audio signatures found - may need different key arrangement")

# Write decrypted file
output_file = "stems_decrypted_test.m4a"
with open(output_file, 'wb') as f:
    # Write unencrypted boxes (ftyp, free)
    f.write(stems_data[:mdat_offset])
    
    # Write decrypted mdat content (update mdat size if needed)
    # Actually, leave size as-is since it's the size on disk
    f.write(bytes(decrypted_payload))

print(f"\n[+] Wrote decrypted file: {output_file}")
print(f"[+] Total output size: {len(stems_data[:mdat_offset]) + len(decrypted_payload)} bytes")

print("\n" + "=" * 80)
print("[*] Next: Verify with FFmpeg")
print("    ffprobe stems_decrypted_test.m4a")
print("=" * 80)
