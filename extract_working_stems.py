#!/usr/bin/env python3
"""
Extract the working 0.7 seconds of all 4 stems as proof of concept
"""

import subprocess
import os

input_file = "stems_partial_1520frames.m4a"
duration = 0.7  # Only first 0.7 seconds properly decrypted

stems = [
    {'name': 'drums', 'ch': 'c0=c0|c1=c1'},
    {'name': 'bass', 'ch': 'c0=c2|c1=c3'},
    {'name': 'melody', 'ch': 'c0=c4|c1=c5'},
    {'name': 'vocals', 'ch': 'c0=c6|c1=c7'},
]

print(f"[*] Extracting working stems (first {duration}s)")
print("=" * 60)

for stem in stems:
    output = f"{stem['name']}_working.wav"
    
    cmd = [
        'ffmpeg',
        '-i', input_file,
        '-t', str(duration),
        '-af', f"pan=stereo|{stem['ch']}",
        '-c:a', 'pcm_s16le',
        '-ar', '44100',
        '-y',
        output
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(output):
        size = os.path.getsize(output)
        print(f"[+] {output:20s} {size:8,d} bytes")
    else:
        print(f"[!] Failed: {output}")

print("\n" + "=" * 60)
print("[*] Test playback:")
print("    ffplay drums_working.wav")
print("    # or double-click the file in Explorer")
print("\n[!] Note: These are WORKING, PLAYABLE files")
print(f"[!] But only {duration}s long (need 21,407 more keys for full 6:45)")
