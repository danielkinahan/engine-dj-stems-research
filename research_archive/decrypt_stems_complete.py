#!/usr/bin/env python3
"""
Full .stems file decryption - CORRECTED VERSION
Includes the moov metadata box at the end
"""

import struct
import re

print("[*] Engine DJ .stems Full Decryption (Complete)")
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

print(f"[+] Read {len(stems_data):,} bytes from {stems_file}")

# Parse MP4 structure
pos = 0
boxes_info = []

while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    
    try:
        box_type_str = box_type.decode('ascii')
    except:
        box_type_str = box_type.hex()
    
    boxes_info.append({
        'offset': pos,
        'type': box_type_str,
        'size': size,
    })
    
    print(f"[*] Box: {box_type_str:4s} offset=0x{pos:08x} size={size:,d}")
    
    pos += size

# Find key boxes
ftyp_offset = None
mdat_offset = None
mdat_size = None
moov_offset = None

for box in boxes_info:
    if box['type'] == 'ftyp':
        ftyp_offset = box['offset']
    elif box['type'] == 'mdat':
        mdat_offset = box['offset']
        mdat_size = box['size']
    elif box['type'] == 'moov':
        moov_offset = box['offset']

print(f"\n[+] Key offsets:")
print(f"    ftyp: 0x{ftyp_offset:x}")
print(f"    mdat payload: 0x{mdat_offset + 8:x} (size: {mdat_size - 8:,} bytes)")
print(f"    moov: 0x{moov_offset:x}")

# Extract parts
ftyp_end = None
for box in boxes_info:
    if box['offset'] == ftyp_offset:
        ftyp_end = ftyp_offset + box['size']
        break

# Get everything up to and including free box
header_data = stems_data[:mdat_offset + 8]

# Get encrypted mdat payload
encrypted_payload = stems_data[mdat_offset + 8:moov_offset]

print(f"\n[*] Decrypting payload ({len(encrypted_payload):,} bytes)...")

# Decrypt using cyclic key pattern
keys_combined = b''.join(keys_bytes)
decrypted_payload = bytearray()

for i, encrypted_byte in enumerate(encrypted_payload):
    key_byte = keys_combined[i % len(keys_combined)]
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_payload.append(decrypted_byte)
    
    if (i + 1) % 5000000 == 0:
        print(f"    [{i+1:,}/{len(encrypted_payload):,}] {100*(i+1)/len(encrypted_payload):.1f}%")

print(f"[+] Decrypted {len(decrypted_payload):,} bytes")

# Get moov box
moov_data = stems_data[moov_offset:]
print(f"[+] Extracted moov box: {len(moov_data):,} bytes")

# Assemble complete file
output_data = bytearray()
output_data.extend(header_data)
output_data.extend(decrypted_payload)
output_data.extend(moov_data)

# Update mdat size in the output
mdat_size_correct = len(decrypted_payload) + 8
output_data[mdat_offset:mdat_offset+4] = struct.pack('>I', mdat_size_correct)

# Write output
output_file = "stems_decrypted_complete.m4a"
with open(output_file, 'wb') as f:
    f.write(output_data)

print(f"\n[+] Wrote complete decrypted file: {output_file}")
print(f"[+] Total file size: {len(output_data):,} bytes")

print("\n" + "=" * 80)
print("[*] Verifying with FFmpeg...")
print("=" * 80)

import subprocess
result = subprocess.run(['ffprobe', output_file, '-v', 'error', '-show_format', '-show_streams'],
                       capture_output=True, text=True)

if result.returncode == 0:
    print(f"\n[+] File is valid MP4!")
    print(result.stdout[:1000])
else:
    print(f"\n[!] FFmpeg reported issues:")
    print(result.stderr[:500])
