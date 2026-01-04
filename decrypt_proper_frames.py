#!/usr/bin/env python3
"""
Proper frame-based decryption using actual frame size (1520 bytes per packet)
"""

import struct
import re

print("[*] Frame-Based Decryption (1520-byte AAC frames)")
print("=" * 60)

# Load all 10 keys
keys = []
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

for match in re.finditer(r'Packet \d+.*?:((?:\s+[a-f0-9]{2})+)', content):
    hex_str = ''.join(match.group(1).split())
    keys.append(bytes.fromhex(hex_str))

print(f"[+] Loaded {len(keys)} keys (128 bytes each)")

# Read file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

# Find mdat
pos = 0
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

mdat_payload_start = mdat_offset + 8
encrypted_payload = stems_data[mdat_payload_start:moov_offset]

# AAC frame size from Frida capture
FRAME_SIZE = 1520

num_frames = len(encrypted_payload) // FRAME_SIZE
print(f"[+] Encrypted payload: {len(encrypted_payload):,} bytes")
print(f"[+] Frame size: {FRAME_SIZE} bytes")
print(f"[+] Total frames: {num_frames} frames")
print(f"[+] Frames we can decrypt: {len(keys)}")

print(f"\n[*] Decrypting first {len(keys)} frames...")

decrypted = bytearray()

# Decrypt frame by frame
for frame_idx in range(len(keys)):
    frame_start = frame_idx * FRAME_SIZE
    frame_end = frame_start + FRAME_SIZE
    
    if frame_end > len(encrypted_payload):
        print(f"[!] Frame {frame_idx+1} would exceed payload")
        break
    
    frame_data = encrypted_payload[frame_start:frame_end]
    key = keys[frame_idx]
    
    # XOR this frame with its key (key repeats within frame)
    for i, byte in enumerate(frame_data):
        key_byte = key[i % len(key)]
        decrypted.append(byte ^ key_byte)
    
    if frame_idx < 3 or frame_idx == len(keys) - 1:
        print(f"    Frame {frame_idx+1}: {len(frame_data)} bytes")

# Append remaining encrypted data
remaining_start = len(keys) * FRAME_SIZE
decrypted.extend(encrypted_payload[remaining_start:])

print(f"\n[+] Decrypted: {len(keys) * FRAME_SIZE:,} bytes")
print(f"[+] Left encrypted: {len(encrypted_payload) - (len(keys) * FRAME_SIZE):,} bytes")

# Verify
if b'Lavc' in bytes(decrypted[:256]):
    print(f"[+] Verification: Found FFmpeg signature ✓")

# Assemble output
output = bytearray()
output.extend(stems_data[:mdat_offset])
output.extend(struct.pack('>I', len(decrypted) + 8))
output.extend(b'mdat')
output.extend(decrypted)
output.extend(stems_data[moov_offset:])

output_file = "stems_partial_1520frames.m4a"
with open(output_file, 'wb') as f:
    f.write(output)

print(f"[+] Wrote {output_file} ({len(output):,} bytes)")

# Test decoding
import subprocess
print(f"\n[*] Testing AAC decoding...")
result = subprocess.run([
    'ffmpeg',
    '-v', 'error',
    '-i', output_file,
    '-t', '5',
    '-f', 'null',
    '-'
], capture_output=True, text=True, timeout=10)

if result.returncode == 0:
    print(f"[+] First 5 seconds decoded successfully!")
else:
    errors = result.stderr.count('Error')
    if errors > 0:
        print(f"[!] Found {errors} decoding errors")
    else:
        print(f"[+] Decoded with warnings only")

print("\n" + "=" * 60)
print("[*] Extract stems with:")
print(f"    ffmpeg -i {output_file} -af 'pan=stereo|c0=c0|c1=c1' drums.wav")
print(f"\n[!] Note: Only first ~1 second properly decrypted ({len(keys)} frames @ ~10 frames/sec)")
print(f"[!] Need to extract {num_frames - len(keys)} more keys for full file")
