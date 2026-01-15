#!/usr/bin/env python3
"""
Analyze the 128-byte frame header in detail
"""

import struct
from pathlib import Path

stems_file = Path("stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems")
data = stems_file.read_bytes()

# Find mdat
pos = 0
while pos < len(data):
    if pos + 8 > len(data):
        break
    size = struct.unpack('>I', data[pos:pos+4])[0]
    atom_type = data[pos+4:pos+8]
    
    if size == 0:
        size = len(data) - pos
    if size < 8:
        break
    
    if atom_type == b'mdat':
        mdat_pos = pos + 8
        print(f"[*] mdat at 0x{mdat_pos:08x}\n")
        
        # Analyze first 3 frames
        for frame_num in range(3):
            frame_start = mdat_pos + (frame_num * 1648)
            frame_header = data[frame_start:frame_start + 128]
            
            print(f"Frame {frame_num} header (128 bytes):")
            print(f"  Full hex: {frame_header.hex()}\n")
            
            # Break down into potential sections
            print(f"  Bytes 0-15 (potential IV):   {frame_header[0:16].hex()}")
            print(f"  Bytes 16-31 (potential key?): {frame_header[16:32].hex()}")
            print(f"  Bytes 32-47:                  {frame_header[32:48].hex()}")
            print(f"  Bytes 48-63:                  {frame_header[48:64].hex()}")
            print(f"  Bytes 64-79:                  {frame_header[64:80].hex()}")
            print(f"  Bytes 80-95:                  {frame_header[80:96].hex()}")
            print(f"  Bytes 96-111:                 {frame_header[96:112].hex()}")
            print(f"  Bytes 112-127:                {frame_header[112:128].hex()}")
            
            # Check for patterns
            print(f"\n  Analysis:")
            print(f"    Unique bytes: {len(set(frame_header))}/128")
            print(f"    All zeros: {frame_header == bytes(128)}")
            print(f"    Repeating pattern: {frame_header[:16] == frame_header[16:32]}")
            print()
        
        break
    
    pos += size
