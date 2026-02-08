#!/usr/bin/env python3
"""
Decrypt Engine DJ .stems files using the discovered AES-128-CBC key.
"""

import struct
from pathlib import Path
from Crypto.Cipher import AES

# The AES key extracted from Engine DJ.exe FUN_140214ea0:
# Obfuscated bytes in binary: A5 D7 62 34 F6 52 EE FC 4C C9 34 88 DC 08 DB EB
# If reversing the -2 operation (adding 2): A7 D9 64 36 F8 54 F0 FE 4E CB 36 8A DE 0A DB ED
AES_KEY = bytes.fromhex("A7D96436F854F0FE4ECB368ADE0ADDED")

def find_mdat_atom(data):
    """Find the mdat atom position and size in the MP4 file."""
    pos = 0
    while pos < len(data) - 8:
        size = struct.unpack('>I', data[pos:pos+4])[0]
        atom_type = data[pos+4:pos+8].decode('ascii', errors='ignore')
        
        if size == 0:
            size = len(data) - pos
        if size < 8:
            break
            
        if atom_type == 'mdat':
            return pos + 8, size - 8  # Return data start and size
        
        pos += size
    
    return None, None

def decrypt_stems_file(stems_file, output_file):
    """Decrypt a stems file and export as raw AAC."""
    
    print(f"[*] Opening {stems_file}...")
    with open(stems_file, 'rb') as f:
        data = f.read()
    
    print(f"[*] File size: {len(data)} bytes")
    
    # Find mdat atom
    mdat_pos, mdat_size = find_mdat_atom(data)
    if mdat_pos is None:
        print("[!] mdat atom not found")
        return False
    
    print(f"[*] mdat atom found at 0x{mdat_pos:08x}, size {mdat_size} bytes")
    
    # Each frame is 1648 bytes: 16-byte IV + 1520-byte encrypted AAC (AES-128-CBC)
    frame_size = 1648
    num_frames = mdat_size // frame_size
    print(f"[*] Total frames: {num_frames}")
    print(f"[*] Using AES-128-CBC (per-frame IV)")
    
    decrypted_data = bytearray()
    
    for frame_num in range(num_frames):
        frame_start = mdat_pos + frame_num * frame_size
        
        # Extract IV (first 16 bytes of frame)
        iv = data[frame_start:frame_start + 16]
        
        # Extract encrypted payload (next 1520 bytes)
        encrypted = data[frame_start + 16:frame_start + 1536]
        
        if len(encrypted) != 1520:
            print(f"[!] Frame {frame_num}: incomplete payload")
            break
        
        # Decrypt using AES-128-CBC
        try:
            cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            decrypted_data.extend(decrypted)
            
            if frame_num < 5:
                # Check for AAC ADTS sync word (0xFFF at start)
                sync_marker = (decrypted[0] << 4) | (decrypted[1] >> 4)
                if sync_marker == 0xFFF:
                    print(f"  ✓ Frame {frame_num}: AAC sync word found!")
                else:
                    print(f"  ? Frame {frame_num}: sync_marker=0x{sync_marker:03X} (expected 0xFFF)")
        except Exception as e:
            print(f"[!] Frame {frame_num}: decryption error: {e}")
            break
    
    # Save decrypted data
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"\n[+] Decrypted {len(decrypted_data)} bytes to {output_file}")
    print(f"[+] Key used: {AES_KEY.hex().upper()}")
    return True

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python decrypt_stems.py <stems_file> [output_file]")
        print("Example: python decrypt_stems.py 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems' output.aac")
        sys.exit(1)
    
    stems_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "decrypted.aac"
    
    success = decrypt_stems_file(stems_file, output_file)
    sys.exit(0 if success else 1)
