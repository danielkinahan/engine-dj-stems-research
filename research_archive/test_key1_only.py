#!/usr/bin/env python3
"""
Simple test: decrypt with just Key 1 and verify the file
"""

import struct
import re
import subprocess

# Load Key 1 only
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

match = re.search(r'Packet 1.*?:((?:\s+[a-f0-9]{2})+)', content)
key1_hex = ''.join(match.group(1).split())
key1 = bytes.fromhex(key1_hex)

print(f"[*] Using Key 1 only ({len(key1)} bytes)\n")

# Read encrypted file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

# Find moov offset
pos = 0
moov_offset = None
while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    if box_type == b'moov':
        moov_offset = pos
        break
    pos += size

mdat_offset = 0x2c
encrypted_payload = stems_data[mdat_offset:moov_offset]

print(f"[*] Decrypting {len(encrypted_payload):,} bytes with Key 1 repeated...")

# Decrypt
decrypted_payload = bytearray()
for i, encrypted_byte in enumerate(encrypted_payload):
    key_byte = key1[i % len(key1)]
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_payload.append(decrypted_byte)

# Assemble file
output_data = bytearray()
output_data.extend(stems_data[:0x24])  # ftyp + free

# Update mdat size
mdat_size = len(decrypted_payload) + 8
output_data.extend(struct.pack('>I', mdat_size))
output_data.extend(b'mdat')

output_data.extend(decrypted_payload)
output_data.extend(stems_data[moov_offset:])

# Write
output_file = "stems_key1_only.m4a"
with open(output_file, 'wb') as f:
    f.write(output_data)

print(f"[+] Wrote {output_file} ({len(output_data):,} bytes)")

# Verify
print(f"\n[*] Verifying with FFprobe...")
result = subprocess.run(['ffprobe', output_file, '-v', 'error', '-show_error'], 
                       capture_output=True, text=True, timeout=5)

if 'error' in result.stdout.lower() or result.returncode != 0:
    print(f"[!] FFprobe reported issues:")
    print(result.stdout[:500])
    print(result.stderr[:500])
else:
    print(f"[+] File appears valid!")
    
# Try decoding a small sample
print(f"\n[*] Trying to decode first 30 seconds...")
result = subprocess.run([
    'ffmpeg', '-i', output_file,
    '-t', '30',
    '-c:a', 'pcm_s16le',
    '-f', 'null', '-',
    '-v', 'error'
], capture_output=True, text=True, timeout=10)

if result.returncode == 0:
    print(f"[+] Successfully decoded first 30 seconds!")
else:
    print(f"[!] Decoding errors detected:")
    if result.stderr:
        print(result.stderr[:500])
