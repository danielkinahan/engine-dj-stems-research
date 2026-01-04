#!/usr/bin/env python3
"""
Alternative decryption: Use only Key 1 repeated
We confirmed Key 1 works for the start of the file and produces Lavc signature
"""

import struct
import re

print("[*] Alternative Decryption - Key 1 Only (Repeated)")
print("=" * 60)

# Load Key 1 only
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

match = re.search(r'Packet 1.*?:((?:\s+[a-f0-9]{2})+)', content)
if not match:
    print("[!] Could not find Key 1")
    exit(1)

key1_hex = ''.join(match.group(1).split())
key1 = bytes.fromhex(key1_hex)

print(f"[+] Loaded Key 1 ({len(key1)} bytes)")

# Read encrypted file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

print(f"[+] Read {len(stems_data):,} bytes from input")

# Find boxes
pos = 0
mdat_offset = None
mdat_size = None
moov_offset = None

while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    
    if box_type == b'mdat':
        mdat_offset = pos
        mdat_size = size
    elif box_type == b'moov':
        moov_offset = pos
        break
    
    pos += size

if mdat_offset is None or moov_offset is None:
    print("[!] Could not find required boxes")
    exit(1)

print(f"[+] mdat at 0x{mdat_offset:x}, moov at 0x{moov_offset:x}")

# Decrypt with Key 1 only
mdat_payload_start = mdat_offset + 8
encrypted_payload = stems_data[mdat_payload_start:moov_offset]

print(f"[*] Decrypting {len(encrypted_payload):,} bytes with Key 1 repeated...")

decrypted = bytearray()
for i, byte in enumerate(encrypted_payload):
    key_byte = key1[i % len(key1)]
    decrypted.append(byte ^ key_byte)
    
    if (i + 1) % 5000000 == 0:
        print(f"    {100*(i+1)/len(encrypted_payload):.0f}%")

print(f"[+] Decryption complete")

# Verify
if b'Lavc' in bytes(decrypted[:256]):
    print(f"[+] Verification: Found FFmpeg signature ✓")
else:
    print(f"[!] Warning: No FFmpeg signature")

# Assemble file
output = bytearray()
output.extend(stems_data[:mdat_offset])  # Headers
output.extend(struct.pack('>I', len(decrypted) + 8))
output.extend(b'mdat')
output.extend(decrypted)
output.extend(stems_data[moov_offset:])  # moov

output_file = "stems_key1_repeated.m4a"
with open(output_file, 'wb') as f:
    f.write(output)

print(f"[+] Wrote {output_file} ({len(output):,} bytes)")

# Test with ffprobe
import subprocess
result = subprocess.run(['ffprobe', output_file, '-v', 'error', '-show_entries', 
                        'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1'],
                       capture_output=True, text=True, timeout=5)

if result.returncode == 0 and result.stdout.strip():
    duration = float(result.stdout.strip())
    print(f"[+] FFprobe reports duration: {duration:.2f} seconds")
    
    if duration > 300:  # More than 5 minutes
        print(f"[+] Duration looks correct! (~{duration/60:.1f} minutes)")
    else:
        print(f"[!] Duration seems short (expected ~6:45 minutes)")
else:
    print(f"[!] FFprobe had issues")

print("\n" + "=" * 60)
print("[*] Now try extracting stems from this file:")
print(f"    py extract_stems_robust.py")
print("[*] Edit the script to use: input_file = '{output_file}'")
