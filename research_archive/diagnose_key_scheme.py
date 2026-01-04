#!/usr/bin/env python3
"""
Since simple repeating key doesn't work, try decrypting only the BEGINNING
and saving just that portion to see if it plays.
"""

import struct

XOR_KEY = bytes([
    0x3a, 0x81, 0xb0, 0x58, 0x70, 0x0c, 0x86, 0x0e, 0xd3, 0xb8, 0xef, 0xe2, 0xdf, 0xb0, 0x7b, 0x61,
    0x02, 0x74, 0x8c, 0xc3, 0x4a, 0xf8, 0x60, 0x4e, 0x2e, 0x0b, 0x74, 0x81, 0x5f, 0x13, 0x5e, 0x6c,
    0x0c, 0xb1, 0x58, 0x44, 0x0f, 0x92, 0x6c, 0xfa, 0x25, 0xc7, 0x8f, 0x16, 0x1e, 0x3a, 0xc3, 0x41,
    0xad, 0xe5, 0x35, 0xc0, 0x83, 0x1c, 0xf6, 0x86, 0x18, 0xf9, 0x57, 0xd3, 0x0f, 0x00, 0x03, 0xe1,
    0x45, 0xfd, 0xa1, 0x3e, 0x8c, 0xbd, 0xbd, 0x9c, 0x93, 0x2d, 0x88, 0x29, 0x69, 0x6d, 0x28, 0x62,
    0x77, 0x00, 0xf8, 0x15, 0xf8, 0x9f, 0x76, 0x86, 0x35, 0x18, 0x92, 0xe4, 0x31, 0x21, 0xa9, 0x35,
    0x52, 0x6e, 0x42, 0x3e, 0x7b, 0x6e, 0xb0, 0xb3, 0x52, 0x9d, 0x56, 0xfa, 0xd6, 0xaf, 0xc6, 0x90,
    0xc1, 0x2b, 0xad, 0xa3, 0x50, 0xf0, 0xcb, 0xef, 0xb6, 0xc4, 0x4f, 0xf8, 0x99, 0xcc, 0x97, 0x39,
])

print("Hypothesis: Maybe only Frame 1 uses this key, and other frames DON'T?")
print("Or Frame 0 is unencrypted (PCE), Frame 1+ encrypted?\n")

# Load the file
stems_file = 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems'
with open(stems_file, 'rb') as f:
    data = bytearray(f.read())

# Find mdat
mdat_pos = data.find(b'mdat')
aac_start = mdat_pos - 4
mdat_size = struct.unpack('>I', data[aac_start:aac_start+4])[0]
aac_offset = aac_start + 8

# From previous analysis, we know frame 0 starts at offset 0xD82 within AAC data
# Let's check if Frame 0 is unencrypted

print("Checking first 2000 bytes of AAC data (should contain Frame 0):\n")

# Try XORing
test_data = data[aac_offset:aac_offset + 2000]
decrypted = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(test_data))

# Look for ADTS sync
for i in range(0, 2000-2):
    if decrypted[i] == 0xFF and (decrypted[i+1] & 0xF0) == 0xF0:
        print(f"Found ADTS sync at offset {i} (0x{i:X})")
        print(f"  Next 16 bytes: {decrypted[i:i+16].hex(' ')}")
        if i == 0:
            print("  -> This might be Frame 0 (unencrypted PCE)")
        break
else:
    print("No ADTS sync found in first 2000 bytes")
    print("First 64 decrypted bytes:")
    print(decrypted[:64].hex(' '))
    
print("\n" + "="*70)
print("CONCLUSION")
print("="*70)
print("The 128-byte key works for BEGINNING, but key must change.")
print("Most likely: Key is derived PER-FRAME using frame index or counter.")
print("\nWithout knowing the key derivation algorithm, we have 2 options:")
print("1. Capture MORE packet/write pairs from Frida to reverse-engineer formula")
print("2. Use Ghidra to find the actual key generation function")
print("\nRecommend: Go back to Ghidra and search for functions that:")
print("  - Take frame_index as parameter")
print("  - Call hash functions (SHA, MD5)")
print("  - Generate 128-byte buffers")
