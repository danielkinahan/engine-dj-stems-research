#!/usr/bin/env python3
"""
Advanced key analysis - try various derivation methods
"""

import hashlib
import hmac

# Our extracted keys (first 16 bytes each)
keys_hex = [
    "3a81b058700c860ed3b8efe2dfb07b61",
    "5d077ad9cd3936d0c958a905088b39f0",
    "1209f67e1b1a003e00ffd9a74a1208e6",
    "9ffa55d49f19be595d07cfdb619d8d22",
    "69dda9d2bb5229b34164b52fb6f12bd4",
    "ecccb9edfafacf3ac10607995acba0d0",
    "ef23613edb7a8488ab729922a6b58fbd",
    "fd3210da84138bc734bf9c4cab01a7bd",
    "e6c37f67091c48a73312cafa1b28e341",
    "71733117e864710ce2f308c4b2047f62",
]

keys = [bytes.fromhex(k) for k in keys_hex]

uuid_str = "0f7da717-a4c6-46be-994e-eca19516836c"
uuid_bytes = uuid_str.encode()
uuid_bytes_bin = bytes.fromhex("0f7da717a4c646be994eeca19516836c")

print("=" * 80)
print("ADVANCED KEY DERIVATION ANALYSIS")
print("=" * 80)

# Test HMAC variants
print("\n[Test] HMAC-MD5(UUID, frame_index):")
for i in range(3):
    h = hmac.new(uuid_bytes, bytes([i + 1]), hashlib.md5).digest()
    print(f"  Frame {i+1}: {h.hex()}")
    print(f"  Expected: {keys_hex[i]}")
    if h.hex() == keys_hex[i]:
        print("    ✓✓✓ MATCH!")

print("\n[Test] HMAC-SHA256(UUID, frame_index):")
for i in range(3):
    h = hmac.new(uuid_bytes, bytes([i + 1]), hashlib.sha256).digest()[:16]
    print(f"  Frame {i+1}: {h.hex()}")
    print(f"  Expected: {keys_hex[i]}")
    if h.hex() == keys_hex[i]:
        print("    ✓✓✓ MATCH!")

# Try CRC32 variants
print("\n[Test] Using frame_index directly (try different patterns):")

# Pattern: simple increment
print("  Pattern 1 - Simple increment:")
for i in range(3):
    print(f"    Frame {i+1}: current={i}, expected={keys_hex[i][:8]}...")

# Try reverse engineering: Look at key1 bytes
print("\n[Analysis] Examining Key structure:")
for i, key in enumerate(keys[:5], 1):
    print(f"  Key {i}: {' '.join(f'{b:02x}' for b in key)}")

# Try pattern matching in keys
print("\n[Pattern Detection]:")
all_bytes = b''.join(keys)
byte_counts = {}
for b in all_bytes:
    byte_counts[b] = byte_counts.get(b, 0) + 1

# Show most common bytes
top_bytes = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:10]
print("  Most common bytes:")
for byte, count in top_bytes:
    print(f"    0x{byte:02x}: {count} times ({100*count/len(all_bytes):.1f}%)")

# Calculate entropy
entropy = 0
for count in byte_counts.values():
    p = count / len(all_bytes)
    entropy -= p * (p and __import__('math').log2(p) or 0)

print(f"\n  Shannon Entropy: {entropy:.2f} bits/byte (max 8.0 for random)")

# Try as hardcoded lookup table approach
print("\n[Hypothesis] Keys might be from a hardcoded lookup table in binary")
print("  Recommendations:")
print("  1. Decompile Engine DJ.exe at 0xb31196 to see key generation")
print("  2. Search for these keys in the binary with strings utility")
print("  3. Check if keys are stored in a data section or DLL")

# Search for hex patterns in the keys
print("\n[Pattern Search] Looking for repeated sequences:")
key_bytes = b''.join(keys)
for size in [2, 4, 8]:
    sequences = {}
    for i in range(0, len(key_bytes) - size):
        seq = key_bytes[i:i+size]
        sequences[seq] = sequences.get(seq, 0) + 1
    
    repeated = [(seq, count) for seq, count in sequences.items() if count > 1]
    if repeated:
        print(f"  {size}-byte sequences repeated more than once:")
        for seq, count in sorted(repeated, key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {seq.hex()}: {count} times")
    else:
        print(f"  {size}-byte sequences: All unique")

print("\n" + "=" * 80)
