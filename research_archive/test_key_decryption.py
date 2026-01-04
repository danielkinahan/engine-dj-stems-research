#!/usr/bin/env python3
"""
Decrypt the full .stems file using our 10 extracted keys
and see if we can infer patterns or additional information
"""

import struct

# All 128 extracted keys (full length)
keys_hex = [
    "3a81b058700c860ed3b8efe2dfb07b61d0aef39e40436329087d780909972900 5a5465f48506 41cb 6118fcd980e2686819 4b7b633f142ae78ab9de2a60df3a04c41949efe6de0a91656dede526ffa72fa071a083c69330577 1c2fa3c69fc6c9dd443f9a77e89c537 3fc9 fde8e2ff3f464f 916a f5 20f6ce6b2c 77860 6fab9c32732",
    "5d07 7a d9cd3936d0c958a905088b39f044f68b3a1bd407 95b3ca5ff869a0a246f6da9d535 84b987f 92387 71f1b861c d7 2fff8f9375 69cae90533 4c552fcc405609755 a56c9b18d5c52 b9f7 660639 0b4f74 e18c 119888 e2c84 8cf6902 c08616 dc84d00b8a d7d926c412 0cc7a14 eca0193 11fa 2b7 ea33e8461488611973 2ff795d",
]

# Let me try a different approach -just work with the keys we have already
# parsed from keys_extracted.txt

with open('keys_extracted.txt', 'r') as f:
    content = f.read()

import re
keys_bytes = []

# Parse all keys from the file
for match in re.finditer(r'Packet \d+.*?:((?:\s+[a-f0-9]{2})+)', content):
    hex_str = ''.join(match.group(1).split())
    keys_bytes.append(bytes.fromhex(hex_str))
    print(f"Loaded key with {len(bytes.fromhex(hex_str))} bytes")

print(f"\n[*] Loaded {len(keys_bytes)} keys")

if not keys_bytes:
    print("[!] Could not load keys")
    exit(1)

# Now try to decrypt sample.stems with these keys
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"

print(f"[*] Attempting to read {stems_file}...")

try:
    with open(stems_file, 'rb') as f:
        stems_data = f.read()
    print(f"[+] Read {len(stems_data)} bytes")
    
    # Look for MP4 ftyp header after encryption 
    print("\n[*] Searching for MP4 signature patterns...")
    
    # XOR the beginning with key 1 and look for 'ftyp' signature
    key1 = keys_bytes[0]
    
    # Try first 1024 bytes
    test_data = stems_data[:1024]
    decrypted_test = bytes(a ^ b for a, b in zip(test_data, (key1 * (len(test_data) // len(key1) + 1))[:len(test_data)]))
    
    print(f"\n[+] First 128 bytes after XOR with Key1:")
    for i in range(0, 128, 16):
        hex_line = ' '.join(f'{b:02x}' for b in decrypted_test[i:i+16])
        ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted_test[i:i+16])
        print(f"  {i:04x}: {hex_line:<48} | {ascii_line}")
    
    # Check for known signatures
    if b'ftyp' in decrypted_test:
        print(f"\n[+] FOUND 'ftyp' signature!")
        offset = decrypted_test.find(b'ftyp')
        print(f"    At offset: 0x{offset:x}")
    else:
        print(f"\n[-] No 'ftyp' signature found in first 128 bytes")
        
    if b'mdat' in decrypted_test:
        print(f"[+] FOUND 'mdat' signature!")
    
    if b'Lavc' in decrypted_test:
        print(f"[+] FOUND 'Lavc' FFmpeg signature!")
        offset = decrypted_test.find(b'Lavc')
        print(f"    At offset: 0x{offset:x}")
        
except FileNotFoundError:
    print(f"[!] File not found: {stems_file}")
except Exception as e:
    print(f"[!] Error: {e}")

print("\n[*] Checking multiple framing approaches...")
print("    1. Is Key1 repeated continuously?")
print("    2. Do Keys 1-10 apply to frames 1-10 sequentially?")
print("    3. Or is there XOR masking across multiple frames?")
