#!/usr/bin/env python3
"""
Extract AES-128 encryption key from Engine DJ.exe binary.

From Ghidra analysis of function FUN_140214ea0:
The key is stored as obfuscated bytes, then each byte has -2 subtracted.
"""

# From the decompiled code at address 140214ea0
# These are the obfuscated key bytes (16 bytes):
obfuscated_key = [
    0xa5,  # -0x5b = -91 in signed byte
    0xd7,
    0x62,
    0x34,
    0xf6,
    0x52,
    0xee,
    0xfc,
    0x4c,
    0xc9,
    0x34,
    0x88,
    0xdc,
    0x08,
    0xdb,
    0xeb,
]

# The code does: local_28[uVar2] = local_28[uVar2] + -2;
# This subtracts 2 from each byte (for uVar2 from 0 to 15)
print("Obfuscated key (as found in binary):")
print(bytes(obfuscated_key).hex().upper())

# De-obfuscate by adding 2 to each byte
actual_key = bytes([(b + 2) & 0xFF for b in obfuscated_key])

print("\nActual AES key (after -2 operation reversal):")
print(actual_key.hex().upper())
print("\nKey bytes:")
print(list(actual_key))

# Save to file
with open("aes_key.hex", "w") as f:
    f.write(actual_key.hex().upper())
    
print("\n[+] Key saved to aes_key.hex")
