#!/usr/bin/env python3
"""
Extract 4 stereo WAV files from the 8-channel decrypted stems file
"""

import subprocess
import os

# The audio is 8 channels:
# Channels 0-1: Drums (stereo)
# Channels 2-3: Bass (stereo)
# Channels 4-5: Melody (stereo)
# Channels 6-7: Vocals (stereo)

input_file = "stems_decrypted_complete.m4a"
stems = [
    {'name': 'drums', 'channels': '0,1', 'channels_text': 'c0 c1'},
    {'name': 'bass', 'channels': '2,3', 'channels_text': 'c2 c3'},
    {'name': 'melody', 'channels': '4,5', 'channels_text': 'c4 c5'},
    {'name': 'vocals', 'channels': '6,7', 'channels_text': 'c6 c7'},
]

print("[*] Extracting 4 stereo stems from 8-channel audio\n")

for stem in stems:
    output_file = f"{stem['name']}.wav"
    
    print(f"[*] Extracting {stem['name'].upper()}...")
    print(f"    Input channels: {stem['channels_text']}")
    print(f"    Output file: {output_file}")
    
    # Use ffmpeg to extract specific channels
    cmd = [
        'ffmpeg',
        '-i', input_file,
        '-filter_complex', f"[0:a]channelsplit=channel_layout=7.1[c0][c1][c2][c3][c4][c5][c6][c7];[{stem['channels_text']}]join=inputs=2:channel_layout=stereo[out]",
        '-map', '[out]',
        '-c:a', 'pcm_s16le',
        '-y',
        output_file
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        file_size = os.path.getsize(output_file)
        print(f"    [+] Success! File size: {file_size:,} bytes\n")
    else:
        print(f"    [!] Error: {result.stderr[:200]}\n")

# Verify the extracted files
print("\n[*] Verification:")
for stem in stems:
    output_file = f"{stem['name']}.wav"
    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        print(f"    ✓ {output_file:15s} - {file_size:12,d} bytes")
    else:
        print(f"    ✗ {output_file:15s} - NOT FOUND")

print("\n[*] Done!")
