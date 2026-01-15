#!/usr/bin/env python3
"""
Compare multiple stems files to find pattern in encryption/key

Key insight: We have 140+ stems files from the SAME TRACK UUID.
Each one has different audio (different remix versions).
If they all use the same key, we can analyze patterns.

Strategy:
1. Load several stems files from the Engine Library (all same UUID)
2. Extract IVs and first encrypted frames
3. If key is same, XOR operations might reveal patterns
4. Look for constants that could be the shared key
"""

from pathlib import Path
import struct

stems_dir = Path("C:\\Users\\Daniel\\Music\\Engine Library\\Stems")

# Get all stems files for the track UUID 0f7da717-a4c6-46be-994e-eca19516836c
target_uuid = "0f7da717-a4c6-46be-994e-eca19516836c"
stems_files = sorted([f for f in stems_dir.glob("*.stems") if target_uuid in f.name])

print(f"[*] Found {len(stems_files)} stems files for track {target_uuid}")
print(f"[*] Files: {[f.name for f in stems_files[:5]]}...\n")

FRAME_SIZE = 1648
HEADER_SIZE = 128

# Extract data from first 5 files
frames_data = []

for stems_path in stems_files[:5]:
    with open(stems_path, 'rb') as f:
        data = f.read()
    
    # Find mdat
    mdat_pos = data.find(b'mdat')
    if mdat_pos == -1:
        continue
    
    frame_start = mdat_pos + 8
    
    # Extract frame 0
    if frame_start + FRAME_SIZE <= len(data):
        frame = data[frame_start:frame_start+FRAME_SIZE]
        iv = frame[0:16]
        header = frame[0:HEADER_SIZE]
        encrypted = frame[HEADER_SIZE:HEADER_SIZE+1520]
        
        frames_data.append({
            'file': stems_path.name,
            'iv': iv,
            'header': header,
            'encrypted': encrypted
        })

print(f"[*] Extracted data from {len(frames_data)} files\n")

# Analyze IVs
print("[*] Analyzing IVs:")
for frame in frames_data:
    print(f"    {frame['file'][:20]:20s} IV: {frame['iv'].hex()}")

# Check if IVs are similar
iv0 = frames_data[0]['iv']
print(f"\n[*] IV comparison (XOR with first IV):")
for frame in frames_data[1:]:
    xor_result = bytes([a ^ b for a, b in zip(iv0, frame['iv'])])
    unique = len(set(xor_result))
    print(f"    {frame['file'][:20]:20s} XOR unique bytes: {unique}/16 - {xor_result.hex()}")

# Analyze headers
print(f"\n[*] Header differences (between files):")
header0 = frames_data[0]['header']
for frame in frames_data[1:]:
    differences = sum(1 for a, b in zip(header0, frame['header']) if a != b)
    print(f"    {frame['file'][:20]:20s} {differences:3d}/128 bytes differ")

# Most important: Check encrypted data patterns
print(f"\n[*] Encrypted data analysis:")
print(f"[*] If key is SAME, then different encrypted data = different plaintext")
print(f"[*] If we can find a pattern in how frames differ, we might find the key")

# Check if any encrypted bytes match at same position
for byte_pos in [0, 16, 32, 64, 128, 256]:
    enc0 = frames_data[0]['encrypted'][byte_pos:byte_pos+16]
    matches = []
    
    for frame in frames_data[1:]:
        enc = frame['encrypted'][byte_pos:byte_pos+16]
        if enc0 == enc:
            matches.append(frame['file'])
    
    if matches:
        print(f"\n[+] Position {byte_pos}: MATCHING encrypted bytes!")
        print(f"    Files: {matches}")
        print(f"    Value: {enc0.hex()}")

print("\n[*] CONCLUSION:")
print("[*] If encrypted bytes match, it means:")
print("[*]   - Either same plaintext at same position")
print("[*]   - Or the files are identical (unlikely)")
print("[*] If they differ, it means different audio (expected)")
print("[*] The key is still hidden in the binary or derived algorithmically")
