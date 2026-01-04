#!/usr/bin/env python3
"""
Check the full MP4 box structure in the encrypted .stems file
"""

import struct

stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"

with open(stems_file, 'rb') as f:
    data = f.read()

print("[*] Analyzing full MP4 box structure\n")

pos = 0
boxes = []

while pos < len(data) - 8:
    size = struct.unpack('>I', data[pos:pos+4])[0]
    box_type = data[pos+4:pos+8]
    
    try:
        box_type_str = box_type.decode('ascii')
    except:
        box_type_str = box_type.hex()
    
    boxes.append((pos, box_type_str, size))
    
    print(f"Offset 0x{pos:08x}: {box_type_str:4s} size={size:12,d} bytes (0x{size:x})")
    
    if size == 0:
        print(f"             [extends to end of file]")
        break
    
    pos += size
    
    if pos > len(data):
        print(f"             [box extends beyond file]")
        break

print(f"\n[*] Total boxes found: {len(boxes)}")
print(f"[*] File size: {len(data):,} bytes")

# Check if there's moov, uuid, mdat, etc.
box_names = [b[1] for b in boxes]

print(f"\n[*] Box sequence: {' -> '.join(box_names)}")

if 'moov' in box_names:
    print("[+] Found moov box (MP4 metadata)")
else:
    print("[-] No moov box found - this is an mdat-only file")

if 'uuid' in box_names:
    print("[+] Found uuid box")

# Check what's after mdat
mdat_idx = None
for i, (pos, name, size) in enumerate(boxes):
    if name == 'mdat':
        mdat_idx = i
        print(f"\n[*] mdat box at index {i}")
        print(f"    mdat offset: 0x{pos:x}")
        print(f"    mdat size: {size:,} bytes")
        break

if mdat_idx is not None and mdat_idx + 1 < len(boxes):
    next_box = boxes[mdat_idx + 1]
    print(f"    Next box: {next_box[1]} at 0x{next_box[0]:x}")
elif mdat_idx is not None:
    print(f"    This is the last box")

# The actual MP4 metadata might be in a UUID box or after mdat
# Let's check for any unencrypted boxes after mdat
if mdat_idx is not None:
    mdat_end = boxes[mdat_idx][0] + boxes[mdat_idx][2]
    print(f"\n[*] Checking content after mdat (offset 0x{mdat_end:x}):")
    
    if mdat_end < len(data) - 8:
        after_mdat = data[mdat_end:mdat_end+256]
        print(f"    Next 64 bytes: {' '.join(f'{b:02x}' for b in after_mdat[:64])}")
        
        # Check for box signature
        after_size = struct.unpack('>I', after_mdat[0:4])[0]
        after_type = after_mdat[4:8]
        try:
            after_type_str = after_type.decode('ascii')
            print(f"    Found box: {after_type_str} size={after_size}")
        except:
            print(f"    Box type: {after_type.hex()}")
    else:
        print("    [*] mdat extends to or beyond end of file")

# Check file footer (last 256 bytes)
print(f"\n[*] File footer (last 256 bytes):")
footer = data[-256:]
print(f"    {' '.join(f'{b:02x}' for b in footer[:64])}")
print(f"    {' '.join(f'{b:02x}' for b in footer[64:128])}")
