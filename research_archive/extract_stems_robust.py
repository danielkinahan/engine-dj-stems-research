#!/usr/bin/env python3
"""
Robust stem extraction with error handling and alternative methods
"""

import subprocess
import os
import sys

input_file = "stems_key1_repeated.m4a"

# Check if input exists
if not os.path.exists(input_file):
    print(f"[!] Input file not found: {input_file}")
    sys.exit(1)

print("[*] Robust Stem Extraction")
print("=" * 60)

# Method 1: Try direct channel extraction (may have errors but should work)
stems = [
    {'name': 'drums', 'channels': '0,1'},
    {'name': 'bass', 'channels': '2,3'},
    {'name': 'melody', 'channels': '4,5'},
    {'name': 'vocals', 'channels': '6,7'},
]

print("\n[Method 1] Direct channel extraction with error recovery\n")

for stem in stems:
    output_file = f"{stem['name']}.wav"
    ch1, ch2 = stem['channels'].split(',')
    
    print(f"[*] Extracting {stem['name'].upper()} (channels {stem['channels']})...")
    
    # Use -err_detect ignore_err to continue despite bitstream errors
    cmd = [
        'ffmpeg',
        '-err_detect', 'ignore_err',
        '-i', input_file,
        '-map', '0:a:0',
        '-af', f'pan=stereo|c0=c{ch1}|c1=c{ch2}',
        '-c:a', 'pcm_s16le',
        '-ar', '44100',
        '-y',
        output_file
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        if file_size > 1000000:  # More than 1MB
            print(f"    [+] Success! {output_file} ({file_size:,} bytes)")
        else:
            print(f"    [!] Warning: File very small ({file_size:,} bytes)")
            print(f"    [!] May contain errors or incomplete audio")
    else:
        print(f"    [!] Failed to create {output_file}")

print("\n" + "=" * 60)

# Method 2: Alternative - extract to 8-channel WAV first, then split
print("\n[Method 2] Extract to 8-channel WAV, then split\n")

print("[*] Step 1: Converting to 8-channel PCM WAV...")

wav_8ch = "stems_8channel.wav"
cmd_8ch = [
    'ffmpeg',
    '-err_detect', 'ignore_err',
    '-i', input_file,
    '-c:a', 'pcm_s16le',
    '-ar', '44100',
    '-y',
    wav_8ch
]

result = subprocess.run(cmd_8ch, capture_output=True, text=True)

if os.path.exists(wav_8ch):
    file_size = os.path.getsize(wav_8ch)
    print(f"[+] Created 8-channel WAV: {wav_8ch} ({file_size:,} bytes)")
    
    print("\n[*] Step 2: Splitting 8-channel WAV into individual stems...")
    
    for stem in stems:
        output_file = f"{stem['name']}_alt.wav"
        ch1, ch2 = stem['channels'].split(',')
        
        cmd = [
            'ffmpeg',
            '-i', wav_8ch,
            '-af', f'pan=stereo|c0=c{ch1}|c1=c{ch2}',
            '-c:a', 'pcm_s16le',
            '-y',
            output_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"    [+] {output_file} ({file_size:,} bytes)")
        else:
            print(f"    [!] Failed: {output_file}")
else:
    print(f"[!] Failed to create 8-channel WAV")

print("\n" + "=" * 60)
print("\n[*] Extraction complete! Check files:")
for stem in stems:
    for suffix in ['', '_alt']:
        fname = f"{stem['name']}{suffix}.wav"
        if os.path.exists(fname):
            size = os.path.getsize(fname)
            duration_est = size / (44100 * 2 * 2)  # sample_rate * channels * bytes_per_sample
            print(f"  - {fname:20s} {size:12,d} bytes (~{duration_est:.1f}s)")

print("\n[*] To play a file:")
print("    ffplay drums.wav")
print("    # or")
print("    Start drums.wav")
