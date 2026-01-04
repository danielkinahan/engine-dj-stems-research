#!/usr/bin/env python3
"""
Test different key application strategies
"""

import struct
import re

# Load all 10 extracted keys
keys_bytes = []
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

for match in re.finditer(r'Packet \d+.*?:((?:\s+[a-f0-9]{2})+)', content):
    hex_str = ''.join(match.group(1).split())
    keys_bytes.append(bytes.fromhex(hex_str))

print("[*] Key Application Strategy Testing\n")

# Read the encrypted .stems file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

# Find mdat
pos = 0
moov_offset = None

while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    
    if box_type == b'moov':
        moov_offset = pos
        break
    
    pos += size

mdat_offset = 0x24
mdat_payload_offset = 0x2c
encrypted_payload = stems_data[mdat_payload_offset:moov_offset]

print(f"[*] Encrypted payload size: {len(encrypted_payload):,} bytes")
print(f"[*] Key 1 size: {len(keys_bytes[0])} bytes\n")

# Strategy 1: Just repeat Key 1
print("[Test 1] Repeating Key 1 continuously...")
key1 = keys_bytes[0]
decrypted_1 = bytearray()

for i, encrypted_byte in enumerate(encrypted_payload):
    key_byte = key1[i % len(key1)]
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_1.append(decrypted_byte)

# Check for signature
if b'Lavc' in bytes(decrypted_1[:256]):
    print("  [+] Found 'Lavc' signature - Key 1 repeating works!")
else:
    print("  [-] No 'Lavc' signature")

# Strategy 2: Apply each key to 1024-byte chunks (one frame each)
print("\n[Test 2] One key per 1024-byte frame...")
frame_size = 1024
decrypted_2 = bytearray()

for frame_idx, start in enumerate(range(0, len(encrypted_payload), frame_size)):
    end = min(start + frame_size, len(encrypted_payload))
    chunk = encrypted_payload[start:end]
    
    key_idx = frame_idx % len(keys_bytes)
    key = keys_bytes[key_idx]
    
    for byte in chunk:
        pos_in_frame = (start + len(decrypted_2) - len(decrypted_2)//frame_size * frame_size) % frame_size
        key_byte = key[pos_in_frame % len(key)]
        decrypted_byte = byte ^ key_byte
        decrypted_2.append(decrypted_byte)
    
    if frame_idx < 3:
        print(f"  Frame {frame_idx}: using Key {key_idx}")

if b'Lavc' in bytes(decrypted_2[:256]):
    print("  [+] Found 'Lavc' signature - Frame-based key works!")
else:
    print("  [-] No 'Lavc' signature")

# Strategy 3: 128-byte chunks per key
print("\n[Test 3] One key per 128-byte chunk...")
chunk_size = 128
decrypted_3 = bytearray()

for chunk_idx, start in enumerate(range(0, len(encrypted_payload), chunk_size)):
    end = min(start + chunk_size, len(encrypted_payload))
    chunk = encrypted_payload[start:end]
    
    key_idx = chunk_idx % len(keys_bytes)
    key = keys_bytes[key_idx]
    
    for i, byte in enumerate(chunk):
        key_byte = key[i]
        decrypted_byte = byte ^ key_byte
        decrypted_3.append(decrypted_byte)

if b'Lavc' in bytes(decrypted_3[:256]):
    print("  [+] Found 'Lavc' signature - 128-byte chunks work!")
    print(f"  First 64 bytes: {' '.join(f'{b:02x}' for b in decrypted_3[:64])}")
else:
    print("  [-] No 'Lavc' signature")

# Strategy 4: Each key applied full length, repeated
print("\n[Test 4] All 10 keys combined and cyclic (current approach)...")
keys_combined = b''.join(keys_bytes)
decrypted_4 = bytearray()

for i, encrypted_byte in enumerate(encrypted_payload):
    key_byte = keys_combined[i % len(keys_combined)]
    decrypted_byte = encrypted_byte ^ key_byte
    decrypted_4.append(decrypted_byte)

if b'Lavc' in bytes(decrypted_4[:256]):
    print("  [+] Found 'Lavc' signature - Combined cyclic works!")
else:
    print("  [-] No 'Lavc' signature")

print("\n[Summary]")
print("  Strategy 1 (Key 1 repeat): Works (we already tested this)")
print("  This suggests the key derivation may be more complex than we thought")
print("  The file may need Frame-specific keys, OR...")
print("  The keys we extracted are only for frames 1-10, but the file has more frames")

# Calculate expected number of frames
print(f"\n[*] Frame count analysis:")
payload_size = len(encrypted_payload)
for frame_sz in [1024, 2048, 4096, 512]:
    num_frames = payload_size / frame_sz
    print(f"  If frame size is {frame_sz:4d} bytes: ~{num_frames:.0f} frames")

print(f"\n  We have 10 keys, duration is ~406 seconds @ 44100 Hz")
print(f"  @ 44100 Hz: 406 * 44100 = 17,908,600 samples")
print(f"  In 1024-byte frames: 17,908,600 / (1024/16) = ~351 frames needed")
print(f"  But we only have 10 keys!")
