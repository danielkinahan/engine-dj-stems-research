#!/usr/bin/env python3
"""
Decrypt only the first 10 AAC frames using our 10 extracted keys
This should give us ~73 seconds of playable audio (10/55 * 405 seconds)
"""

import struct
import re

print("[*] Partial Decryption - First 10 Frames Only")
print("=" * 60)

# Load all 10 keys
keys = []
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

for match in re.finditer(r'Packet \d+.*?:((?:\s+[a-f0-9]{2})+)', content):
    hex_str = ''.join(match.group(1).split())
    keys.append(bytes.fromhex(hex_str))

print(f"[+] Loaded {len(keys)} keys")

# Read file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

# Find mdat
pos = 0
mdat_offset = None
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

mdat_payload_start = mdat_offset + 8
encrypted_payload = stems_data[mdat_payload_start:moov_offset]

print(f"[+] Total encrypted payload: {len(encrypted_payload):,} bytes")

# Average frame size is ~592KB, so 10 frames = ~5.92MB
# We'll decrypt using each key for its respective 128-byte block repeatedly through each frame
frame_size_est = len(encrypted_payload) // 55  # 55 frames total
decrypt_size = frame_size_est * 10  # First 10 frames

print(f"[*] Estimated frame size: {frame_size_est:,} bytes")
print(f"[*] Decrypting first 10 frames: {decrypt_size:,} bytes")

decrypted = bytearray()

# Decrypt first 10 frames: apply each key to its frame
for frame_idx in range(10):
    frame_start = frame_idx * frame_size_est
    frame_end = min((frame_idx + 1) * frame_size_est, len(encrypted_payload))
    frame_data = encrypted_payload[frame_start:frame_end]
    
    key = keys[frame_idx]
    
    # XOR this frame with its key (key repeats within frame)
    for i, byte in enumerate(frame_data):
        key_byte = key[i % len(key)]
        decrypted.append(byte ^ key_byte)
    
    print(f"    Frame {frame_idx+1}: {len(frame_data):,} bytes decrypted")

# Keep the rest encrypted (or zero it out to make a shorter file)
print(f"\n[*] Decrypted: {len(decrypted):,} bytes")
print(f"[*] Remaining: {len(encrypted_payload) - len(decrypted):,} bytes (left encrypted)")

# Verify
if b'Lavc' in bytes(decrypted[:256]):
    print(f"[+] Verification: Found FFmpeg signature ✓")

# Assemble file - just first 10 frames
output = bytearray()
output.extend(stems_data[:mdat_offset])  # Headers

# Write shortened mdat with only 10 frames
output.extend(struct.pack('>I', len(decrypted) + 8))
output.extend(b'mdat')
output.extend(decrypted)

# Note: moov box refers to 55 frames, so playback may stop or loop
# Ideally we'd edit moov to say 10 frames, but that's complex
output.extend(stems_data[moov_offset:])

output_file = "stems_first10frames.m4a"
with open(output_file, 'wb') as f:
    f.write(output)

print(f"[+] Wrote {output_file} ({len(output):,} bytes)")

# Test
import subprocess
result = subprocess.run(['ffprobe', output_file, '-v', 'error', '-show_entries',
                        'format=duration', '-of', 'default=noprint_wrappers=1:nokey=1'],
                       capture_output=True, text=True, timeout=5)

if result.returncode == 0 and result.stdout.strip():
    duration = float(result.stdout.strip())
    print(f"[+] Reported duration: {duration:.2f} seconds (~{duration:.1f}s)")
    print(f"    Expected: ~{405 * 10 / 55:.1f}s for 10/55 frames")

print("\n" + "=" * 60)
print("[*] Try extracting stems now:")
print("    ffmpeg -i stems_first10frames.m4a -af 'pan=stereo|c0=c0|c1=c1' drums_10f.wav")
print("\n[!] Note: This file only contains ~73 seconds of the original 6:45")
print("[!] To get full audio, we need to extract the remaining 45 keys")
