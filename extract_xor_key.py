#!/usr/bin/env python3
"""
Extract XOR key by comparing unencrypted FFmpeg output with encrypted file write.
"""

# Packet #1 - UNENCRYPTED from FFmpeg (first 128 bytes)
unencrypted = bytes.fromhex("""
de 04 00 4c 61 76 63 35 38 2e 31 33 34 2e 31 30
30 00 42 36 07 ea 8b 25 1a 23 41 33 ed f1 ce 7b
71 cf 1b d7 73 57 ab 94 85 55 94 00 a0 1c 6b 90
43 7b 2f 1f db fd ce 4a 33 e8 f3 fe 51 e4 2d 9c
b1 ef c1 ef 7b 1e 55 e8 8c 53 2d 55 09 8b df fb
1d ee 71 63 ae 51 ae 4d ad a7 ea f3 db c4 98 c7
09 46 fd 60 78 a7 a6 56 09 d9 2d c6 3b ff d4 45
bb f6 f8 98 02 2c 24 44 e1 01 11 01 06 22 19 a8
""".replace('\n', '').replace(' ', ''))

# WriteFile #2469 - ENCRYPTED (262144 bytes write, likely contains all frames)
encrypted = bytes.fromhex("""
e4 85 b0 14 11 7a e5 3b eb 96 de d1 eb 9e 4a 51
32 74 ce f5 4d 12 eb 6b 34 28 35 b2 b2 e2 90 17
7d 7e 43 93 7c c5 c7 6e a0 92 1b 16 be 26 a8 d1
ee 9e 1a df 58 e1 38 cc 2b 11 a4 2d 5e e4 2e 7d
f4 12 60 d1 f7 a3 e8 74 1f 7e a5 7c 60 e6 f7 99
6a ee 89 76 56 ce d8 cb 98 bf 78 17 ea e5 31 f2
5b 28 bf 5e 03 c9 16 e5 5b 44 7b 3c ed 50 12 d5
7a dd 55 3b 52 dc ef ab 57 c5 5e f9 9f ee 8e 91
""".replace('\n', '').replace(' ', ''))

print("="*70)
print("XOR KEY EXTRACTION")
print("="*70)

print(f"\nUnencrypted length: {len(unencrypted)} bytes")
print(f"Encrypted length: {len(encrypted)} bytes")

# XOR to get the key
xor_key = bytes(u ^ e for u, e in zip(unencrypted, encrypted))

print("\nXOR KEY (first 128 bytes):")
for i in range(0, len(xor_key), 16):
    hex_part = ' '.join(f'{b:02x}' for b in xor_key[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in xor_key[i:i+16])
    print(f"  {i:04x}: {hex_part:<48}  {ascii_part}")

print("\nXOR KEY as Python bytes:")
print("xor_key = bytes([")
for i in range(0, len(xor_key), 16):
    hex_vals = ', '.join(f'0x{b:02x}' for b in xor_key[i:i+16])
    print(f"    {hex_vals},")
print("])")

# Check if there's a pattern
print("\n" + "="*70)
print("PATTERN ANALYSIS")
print("="*70)

# Check for repeating patterns
for pattern_len in [4, 8, 16, 32, 64]:
    if pattern_len * 2 <= len(xor_key):
        pattern1 = xor_key[:pattern_len]
        pattern2 = xor_key[pattern_len:pattern_len*2]
        if pattern1 == pattern2:
            print(f"\n✓ Found repeating {pattern_len}-byte pattern!")
            break
else:
    print("\n✗ No simple repeating pattern found")
    print("Key is likely derived per-frame or uses stream cipher")

# Verify the XOR works
print("\n" + "="*70)
print("VERIFICATION")
print("="*70)

decrypted = bytes(e ^ k for e, k in zip(encrypted, xor_key))
if decrypted == unencrypted:
    print("✓ XOR decryption SUCCESSFUL!")
    print("✓ Key is correct for this frame")
else:
    print("✗ Decryption failed - data mismatch")

print("\n" + "="*70)
print("Next step: Find if key repeats for frame 2, 3, etc.")
print("="*70)
