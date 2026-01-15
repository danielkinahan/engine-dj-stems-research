#!/usr/bin/env python3
"""Compare two stems files from the same track to find patterns"""

from pathlib import Path
from Crypto.Cipher import AES
import hashlib

# Load both stems files
file1 = Path("stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems")
file2 = Path("stems/2 0f7da717-a4c6-46be-994e-eca19516836c.stems")

data1 = file1.read_bytes()
data2 = file2.read_bytes()

print("[*] Comparing two stems files from same track UUID")
print(f"[*] File 1: {len(data1):,} bytes")
print(f"[*] File 2: {len(data2):,} bytes")

# Find mdat in both
mdat1 = data1.find(b'mdat')
mdat2 = data2.find(b'mdat')

frame_start1 = mdat1 + 8
frame_start2 = mdat2 + 8

# Extract first frame from each
FRAME_SIZE = 1648
HEADER_SIZE = 128

# Frame 1 - File 1
frame1_f1 = data1[frame_start1:frame_start1+FRAME_SIZE]
iv1_f1 = frame1_f1[0:16]
header1_f1 = frame1_f1[0:HEADER_SIZE]
encrypted1_f1 = frame1_f1[HEADER_SIZE:HEADER_SIZE+1520]

# Frame 1 - File 2  
frame1_f2 = data2[frame_start2:frame_start2+FRAME_SIZE]
iv1_f2 = frame1_f2[0:16]
header1_f2 = frame1_f2[0:HEADER_SIZE]
encrypted1_f2 = frame1_f2[HEADER_SIZE:HEADER_SIZE+1520]

print(f"\n[*] File 1 Frame 0 IV: {iv1_f1.hex()}")
print(f"[*] File 2 Frame 0 IV: {iv1_f2.hex()}")
print(f"[*] IVs identical: {iv1_f1 == iv1_f2}")

# Compare headers
print(f"\n[*] Headers identical: {header1_f1 == header1_f2}")
if header1_f1 != header1_f2:
    print("[*] Differences in header:")
    for i in range(HEADER_SIZE):
        if header1_f1[i] != header1_f2[i]:
            print(f"    Offset {i:3d}: {header1_f1[i]:02x} vs {header1_f2[i]:02x}")

# Compare encrypted data
print(f"\n[*] Encrypted data identical: {encrypted1_f1 == encrypted1_f2}")
if encrypted1_f1 == encrypted1_f2:
    print("[!] SAME encrypted data means SAME plaintext audio!")
    print("[!] Since IVs are different, key derivation might use IV")
    
# Test if key could be derived from IV
print("\n[*] Testing if key could be derived from IV...")

def test_key_derivation(iv, encrypted, description):
    """Test various key derivation methods from IV"""
    
    # Method 1: Direct MD5 of IV
    key = hashlib.md5(iv).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(encrypted[32:])
    if dec[0] == 0xFF and (dec[1] & 0xF0) == 0xF0:
        print(f"[+] {description}: MD5(IV) works!")
        return key
    
    # Method 2: SHA256 truncated
    key = hashlib.sha256(iv).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(encrypted[:32])
    if dec[0] == 0xFF and (dec[1] & 0xF0) == 0xF0:
        print(f"[+] {description}: SHA256(IV)[:16] works!")
        return key
    
    # Method 3: IV repeated and XORed
    key = bytes([iv[i % 16] ^ iv[(i+8) % 16] for i in range(16)])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(encrypted[:32])
    if dec[0] == 0xFF and (dec[1] & 0xF0) == 0xF0:
        print(f"[+] {description}: IV XOR pattern works!")
        return key
    
    # Method 4: IV + UUID combined
    uuid_bytes = bytes.fromhex('0f7da717a4c646be994eeca19516836c')
    combined = iv + uuid_bytes
    key = hashlib.md5(combined).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(encrypted[:32])
    if dec[0] == 0xFF and (dec[1] & 0xF0) == 0xF0:
        print(f"[+] {description}: MD5(IV+UUID) works!")
        return key
    
    # Method 5: Header bytes as key
    for offset in [16, 32, 48, 64, 80, 96, 112]:
        key_candidate = frame1_f1[offset:offset+16]
        cipher = AES.new(key_candidate, AES.MODE_CBC, iv)
        dec = cipher.decrypt(encrypted[:32])
        if dec[0] == 0xFF and (dec[1] & 0xF0) == 0xF0:
            print(f"[+] {description}: Header bytes at offset {offset} works!")
            return key_candidate
    
    return None

key1 = test_key_derivation(iv1_f1, encrypted1_f1, "File 1")
key2 = test_key_derivation(iv1_f2, encrypted1_f2, "File 2")

if key1:
    print(f"\n[+] Found working key for File 1: {key1.hex()}")
if key2:
    print(f"[+] Found working key for File 2: {key2.hex()}")

if not key1 and not key2:
    print("\n[-] None of the tested derivation methods worked")
    print("[*] Key is likely derived from:")
    print("    - Track metadata not in the file")
    print("    - A master secret in the firmware")
    print("    - Hardware-specific values")
    print("    - Or requires multiple frames to discover pattern")
