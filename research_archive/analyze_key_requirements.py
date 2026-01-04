#!/usr/bin/env python3
"""
Analyze the encryption key requirements
Check how many AAC frames exist vs how many keys we have
"""

import subprocess
import re

print("[*] Analyzing Encryption Key Requirements")
print("=" * 60)

# Get frame count from the decrypted file
result = subprocess.run([
    'ffprobe', 
    'stems_key1_repeated.m4a',
    '-v', 'error',
    '-select_streams', 'a:0',
    '-count_frames',
    '-show_entries', 'stream=nb_read_frames',
    '-of', 'default=noprint_wrappers=1:nokey=1'
], capture_output=True, text=True)

if result.returncode == 0 and result.stdout.strip():
    frame_count = int(result.stdout.strip())
    print(f"[+] AAC frames in file: {frame_count:,}")
else:
    print("[!] Could not get frame count")
    frame_count = None

# Check keys we have
with open('keys_extracted.txt', 'r') as f:
    content = f.read()

keys_found = len(re.findall(r'Packet \d+', content))
print(f"[+] Keys extracted: {keys_found}")

if frame_count:
    print(f"\n[*] Analysis:")
    print(f"    Frames needed: {frame_count:,}")
    print(f"    Keys available: {keys_found}")
    print(f"    Missing keys: {frame_count - keys_found:,}")
    
    print(f"\n[!] PROBLEM IDENTIFIED:")
    print(f"    We need {frame_count:,} unique keys (one per AAC frame)")
    print(f"    But we only extracted {keys_found} keys")
    print(f"    Simply repeating keys causes AAC decode errors")

# Check payload size
import struct
with open('stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems', 'rb') as f:
    data = f.read()

pos = 0
while pos < len(data) - 8:
    size = struct.unpack('>I', data[pos:pos+4])[0]
    box_type = data[pos+4:pos+8]
    if box_type == b'mdat':
        mdat_size = size - 8
        print(f"\n[*] Encrypted payload size: {mdat_size:,} bytes")
        break
    pos += size

if frame_count:
    avg_frame_size = mdat_size / frame_count
    print(f"[*] Average frame size: {avg_frame_size:.0f} bytes")
    
    print(f"\n[*] Key application strategies to test:")
    print(f"    1. Each 128-byte key block → one AAC frame")
    print(f"       {mdat_size} bytes / 128 = {mdat_size/128:.0f} key blocks")
    print(f"    2. Each key repeated per fixed-size chunk")
    print(f"       Need to identify chunk size pattern")

print("\n" + "=" * 60)
print("[*] NEXT STEPS:")
print("    Option A: Extract more keys (need ~17,000 more)")
print("    Option B: Reverse engineer key generation algorithm")
print("    Option C: Use the 10 keys on first 10 frames only")
print("\n[*] Let's try Option C - decrypt just first 10 frames:")
