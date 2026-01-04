#!/usr/bin/env python3
"""
Parse MP4 structure to find where encrypted data starts
"""

import struct

stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"

with open(stems_file, 'rb') as f:
    data = f.read(4096)

print("[*] Parsing MP4 structure from .stems file\n")

pos = 0

# Parse boxes
def parse_box(data, offset):
    if offset + 8 > len(data):
        return None, None, None
    
    size = struct.unpack('>I', data[offset:offset+4])[0]
    box_type = data[offset+4:offset+8]
    
    return size, box_type, offset

while pos < len(data) - 8:
    size, box_type, offset = parse_box(data, pos)
    
    if box_type is None:
        break
    
    try:
        box_type_str = box_type.decode('ascii')
    except:
        box_type_str = box_type.hex()
    
    print(f"[Box] Type: {box_type_str:4s} | Offset: 0x{pos:08x} | Size: {size} bytes (0x{size:x})")
    
    # Show first 32 bytes of box content
    content_preview = data[pos+8:min(pos+8+32, len(data))]
    print(f"       Content: {' '.join(f'{b:02x}' for b in content_preview)}")
    
    if box_type_str == 'mdat':
        # The actual media data - this is what should be encrypted
        print(f"\n[!] Found 'mdat' box - this is where encrypted data should be")
        print(f"    mdat content starts at offset 0x{pos+8:x}")
        print(f"    mdat size is {size} bytes (payload size: {size-8} bytes)")
        
        # Try XORing the first part with key 1
        print(f"\n[*] Testing XOR with extracted Key 1...")
        
        import re
        with open('keys_extracted.txt', 'r') as kf:
            keys_content = kf.read()
        
        # Parse key 1
        match = re.search(r'Packet 1.*?:((?:\s+[a-f0-9]{2})+)', keys_content)
        if match:
            key1_hex = ''.join(match.group(1).split())
            key1 = bytes.fromhex(key1_hex)
            
            # XOR first 128 bytes of mdat
            mdat_start = pos + 8
            mdat_chunk = data[mdat_start:mdat_start+128]
            
            decrypted = bytes(a ^ b for a, b in zip(mdat_chunk, key1))
            
            print(f"    Encrypted: {mdat_chunk.hex()}")
            print(f"    Key 1:     {key1.hex()}")
            print(f"    Decrypted: {decrypted.hex()}")
            
            # Check for FFmpeg signature
            if b'Lavc' in decrypted:
                print(f"\n    [+] FOUND 'Lavc' signature in decrypted data!")
                print(f"        XOR with Key 1 is correct!")
            else:
                print(f"\n    [-] No 'Lavc' signature found")
                print(f"    Looking for ASCII patterns...")
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted)
                print(f"    ASCII: {ascii_part}")
        
    pos += size
    
    if pos > len(data):
        break

print("\n" + "=" * 80)
print("[CONCLUSION] File structure:")
print("  - First part: Unencrypted MP4 box structure (ftyp, free, mdat headers)")
print("  - mdat payload: Encrypted with per-frame XOR keys")
print("=" * 80)
