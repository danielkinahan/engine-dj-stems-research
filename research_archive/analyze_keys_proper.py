#!/usr/bin/env python3
"""
Analyze the 10 extracted keys from keys_extracted.txt
"""

import hashlib
import re

# Read keys from file
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

# Parse keys
keys_hex = []
for match in re.finditer(r'Packet \d+.*?:\n((?:[a-f0-9]{2} )+)', content):
    hex_str = match.group(1).replace(' ', '')
    keys_hex.append(hex_str)

if not keys_hex:
    print("Could not parse keys from file!")
    exit(1)

# Convert to bytes
keys = [bytes.fromhex(k) for k in keys_hex]

print("=" * 80)
print(f"KEY DERIVATION ANALYSIS - {len(keys)} Extracted Keys")
print("=" * 80)

print(f"\n[*] Found {len(keys)} keys, each {len(keys[0])} bytes\n")

# Show first key (Frame 1)
print(f"Frame 1 Key: {keys[0][:32].hex()}...")

# Test hash-based derivation with UUID from filename
uuid_str = "0f7da717-a4c6-46be-994e-eca19516836c"
uuid_bytes = uuid_str.encode()
uuid_bytes_bin = bytes.fromhex("0f7da717a4c646be994eeca19516836c")  # Binary UUID

print(f"\nTesting hash-based derivation patterns with UUID: {uuid_str}\n")

# Test 1: MD5(UUID + frame_index)
print("[Test 1] MD5(UUID + frame_index):")
for frame_idx in range(1, min(4, len(keys) + 1)):
    test_data = uuid_bytes + bytes([frame_idx])
    md5_hash = hashlib.md5(test_data).digest()
    print(f"  Frame {frame_idx}: {md5_hash.hex()}")
    if md5_hash == keys[frame_idx - 1][:16]:
        print(f"    ✓✓✓ PARTIAL MATCH (first 16 bytes)!")

# Test 2: SHA256(UUID + frame_index)
print("\n[Test 2] SHA256(UUID + frame_index):")
for frame_idx in range(1, min(4, len(keys) + 1)):
    test_data = uuid_bytes + bytes([frame_idx])
    sha256_hash = hashlib.sha256(test_data).digest()
    print(f"  Frame {frame_idx}: {sha256_hash[:16].hex()}...")
    if sha256_hash[:16] == keys[frame_idx - 1][:16]:
        print(f"    ✓✓✓ PARTIAL MATCH!")
    if sha256_hash == keys[frame_idx - 1]:
        print(f"    ✓✓✓ FULL MATCH!")

# Test 3: MD5(binary UUID + frame_index)
print("\n[Test 3] MD5(binary UUID + frame_index):")
for frame_idx in range(1, min(4, len(keys) + 1)):
    test_data = uuid_bytes_bin + bytes([frame_idx])
    md5_hash = hashlib.md5(test_data).digest()
    print(f"  Frame {frame_idx}: {md5_hash.hex()}")
    if md5_hash == keys[frame_idx - 1][:16]:
        print(f"    ✓✓✓ PARTIAL MATCH!")

# Test 4: Simple XOR stream (constant difference)
print("\n[Test 4] Check for constant XOR difference between keys:")
if len(keys) > 1:
    xor_12 = bytes(a ^ b for a, b in zip(keys[0][:16], keys[1][:16]))
    xor_23 = bytes(a ^ b for a, b in zip(keys[1][:16], keys[2][:16]))
    
    print(f"  Key[2] XOR Key[1]: {xor_12.hex()}")
    print(f"  Key[3] XOR Key[2]: {xor_23.hex()}")
    
    if xor_12 == xor_23:
        print("  ✓ CONSTANT XOR DIFFERENCE - Simple stream cipher!")
    else:
        print("  ✗ Differences vary - Not simple stream cipher")

# Test 5: Show all first 16 bytes for visual inspection
print("\n[Test 5] First 16 bytes of each key (for manual inspection):")
for i, key in enumerate(keys, 1):
    print(f"  Key {i}: {key[:16].hex()}")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
