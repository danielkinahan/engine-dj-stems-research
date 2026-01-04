#!/usr/bin/env python3
"""
Analyze AAC frame boundaries to understand key application
"""

import struct
import re

# Load Key 1
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

match = re.search(r'Packet 1.*?:((?:\s+[a-f0-9]{2})+)', content)
key1_hex = ''.join(match.group(1).split())
key1 = bytes.fromhex(key1_hex)

# Read encrypted file
stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
with open(stems_file, 'rb') as f:
    stems_data = f.read()

# Get mdat payload
pos = 0
moov_offset = None
while pos < len(stems_data) - 8:
    size = struct.unpack('>I', stems_data[pos:pos+4])[0]
    box_type = stems_data[pos+4:pos+8]
    if box_type == b'moov':
        moov_offset = pos
        break
    pos += size

mdat_offset = 0x2c
encrypted_payload = stems_data[mdat_offset:moov_offset]

print("[*] Analyzing AAC frame boundaries in encrypted data\n")

# Try to find ADTS sync words by decrypting with Key 1
print("[*] Decrypting first 8KB with Key 1 to find ADTS patterns...")

chunk = encrypted_payload[:8192]
decrypted = bytearray()
for i, byte in enumerate(chunk):
    key_byte = key1[i % len(key1)]
    decrypted_byte = byte ^ key_byte
    decrypted.append(decrypted_byte)

# Look for FFmpeg header + ADTS sync words
print("\n[*] Checking for known signatures:")
if b'Lavc' in bytes(decrypted[:256]):
    lavc_pos = bytes(decrypted).find(b'Lavc')
    print(f"[+] Found Lavc at offset {lavc_pos}")
    
    # ADTS frames come after the FFmpeg container header
    # Look for ADTS sync word (0xFF 0xF?)
    print(f"\n[*] Searching for ADTS frames...")
    for i in range(lavc_pos, min(lavc_pos + 1024, len(decrypted) - 1)):
        if decrypted[i] == 0xFF and (decrypted[i+1] & 0xF0) == 0xF0:
            print(f"[+] ADTS sync at offset {i}: 0x{decrypted[i]:02x} 0x{decrypted[i+1]:02x}")
            
            # ADTS frame size (11 bits starting after sync + version)
            if i + 3 < len(decrypted):
                frame_len_bits = ((decrypted[i+3] & 0x03) << 8) | decrypted[i+4]
                print(f"    Frame length: {frame_len_bits} bytes")
            
            # Only show first 5
            if i > lavc_pos + 500:
                break

# Print hex dump of decrypted start
print("\n[*] First 256 bytes (decrypted with Key 1):")
for i in range(0, 256, 16):
    hex_line = ' '.join(f'{b:02x}' for b in decrypted[i:i+16])
    ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[i:i+16])
    print(f"  {i:04x}: {hex_line:<48} | {ascii_line}")
