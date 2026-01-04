#!/usr/bin/env python3
"""
Split 8-channel decrypted stems audio into individual stem files
Each channel typically represents a different instrument/layer
"""
import os
import subprocess
import sys

def split_stems(input_file, output_dir="stems_extracted"):
    """Split 8-channel M4A into individual WAV files"""
    
    if not os.path.exists(input_file):
        print(f"[!] Error: {input_file} not found")
        return False
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 70)
    print("STEMS SPLITTER - Extract individual channels from decrypted audio")
    print("=" * 70)
    print()
    
    print(f"[*] Input file: {input_file}")
    print(f"[*] Output directory: {output_dir}")
    print()
    
    # Get file info first
    print("[*] Analyzing audio file...")
    cmd_info = [
        'ffprobe',
        '-v', 'quiet',
        '-print_format', 'json',
        '-show_streams',
        input_file
    ]
    
    result = subprocess.run(cmd_info, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Error reading file info")
        return False
    
    print()
    
    # Extract each channel
    channel_names = [
        "Drums",        # Channel 0
        "Bass",         # Channel 1
        "Vocals",       # Channel 2
        "Other Melodic", # Channel 3
        "Harmonic",     # Channel 4
        "Effects",      # Channel 5
        "Ambient",      # Channel 6
        "Background"    # Channel 7
    ]
    
    print("[*] Extracting channels:")
    print()
    
    for ch in range(8):
        name = channel_names[ch] if ch < len(channel_names) else f"Channel {ch}"
        output_file = os.path.join(output_dir, f"stem_{ch:02d}_{name.replace(' ', '_')}.wav")
        
        print(f"    [{ch}] {name:20s} -> {os.path.basename(output_file)}", end='', flush=True)
        
        # Use ffmpeg to extract single channel
        # Format: pan=mono|c0=cN where N is the channel number
        cmd = [
            'ffmpeg',
            '-i', input_file,
            '-filter_complex', f'[0:a]pan=mono|c0=c{ch}[out]',
            '-map', '[out]',
            '-y',  # Overwrite without asking
            '-loglevel', 'error',
            output_file
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            size = os.path.getsize(output_file)
            print(f" ✓ ({size:,} bytes)")
        else:
            print(f" ✗ ERROR")
            print(f"       {result.stderr}")
            return False
    
    print()
    print("[+] All stems extracted successfully!")
    print()
    
    # List output files
    print("[*] Generated files:")
    for fname in sorted(os.listdir(output_dir)):
        fpath = os.path.join(output_dir, fname)
        size = os.path.getsize(fpath)
        print(f"    {fname:50s} {size:12,} bytes")
    
    print()
    print("[+] You can now listen to each stem individually to verify the decryption!")
    
    return True

def main():
    if len(sys.argv) < 2:
        input_file = "FULLY_DECRYPTED_AUDIO.m4a"
    else:
        input_file = sys.argv[1]
    
    output_dir = "stems_extracted"
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    success = split_stems(input_file, output_dir)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
