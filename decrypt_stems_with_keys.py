#!/usr/bin/env python3
"""
Decrypt .stems files using extracted .keys files
"""
import struct
from pathlib import Path
import sys

def load_keys(keys_file):
    """Load keys from a .keys file"""
    keys = []
    with open(keys_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                keys.append(bytes.fromhex(line))
    return keys

def decrypt_stems(stems_file, keys_file, output_file):
    """Decrypt a .stems file using keys from .keys file"""
    
    print(f"[*] Loading keys from: {keys_file}")
    keys = load_keys(keys_file)
    print(f"[+] Loaded {len(keys):,} keys")
    
    print(f"[*] Reading stems file: {stems_file}")
    with open(stems_file, 'rb') as f:
        full_file = f.read()
    
    # Find mdat
    mdat_pos = full_file.find(b'mdat')
    mdat_start = mdat_pos - 4
    mdat_size = struct.unpack('>I', full_file[mdat_start:mdat_start+4])[0]
    data_start = mdat_start + 8
    
    print(f"[+] mdat size: {mdat_size:,} bytes")
    
    # Decrypt all frames
    FRAME_SIZE = 1520
    decrypted_audio = bytearray()
    
    offset = data_start + 4 + 128  # Skip seed + first key
    
    for frame_idx in range(len(keys)):
        # Read encrypted frame
        encrypted_frame = full_file[offset:offset+FRAME_SIZE]
        
        if len(encrypted_frame) < FRAME_SIZE:
            print(f"[!] Frame {frame_idx}: incomplete ({len(encrypted_frame)} bytes)")
            break
        
        # Decrypt with XOR (key repeats to cover 1520 bytes)
        key = keys[frame_idx]
        key_extended = (key * (FRAME_SIZE // 128 + 1))[:FRAME_SIZE]
        decrypted_frame = bytes(a ^ b for a, b in zip(encrypted_frame, key_extended))
        decrypted_audio.extend(decrypted_frame)
        
        # Move to next frame (skip next key)
        offset += FRAME_SIZE + 128
        
        if (frame_idx + 1) % 1000 == 0:
            print(f"  Decrypted {frame_idx + 1:,} frames...")
    
    print(f"[+] Total decrypted: {len(decrypted_audio):,} bytes")
    
    # Check for AAC sync
    sync_count = 0
    for i in range(0, min(2000, len(decrypted_audio)-1)):
        word = (decrypted_audio[i] << 8) | decrypted_audio[i+1]
        if (word & 0xfff0) == 0xfff0:
            if sync_count == 0:
                print(f"[+] First AAC sync at offset {i}")
            sync_count += 1
            if sync_count >= 3:
                break
    
    # Reconstruct MP4
    print(f"[*] Reconstructing MP4...")
    
    # Extract ftyp
    ftyp_size = struct.unpack('>I', full_file[0:4])[0]
    ftyp = full_file[0:ftyp_size]
    
    # Extract moov
    moov_pos = full_file.find(b'moov') - 4
    moov_size = struct.unpack('>I', full_file[moov_pos:moov_pos+4])[0]
    moov = full_file[moov_pos:moov_pos+moov_size]
    
    # Create new mdat
    new_mdat_size = len(decrypted_audio) + 8
    new_mdat = struct.pack('>I', new_mdat_size) + b'mdat' + decrypted_audio
    
    # Write output
    with open(output_file, 'wb') as out:
        out.write(ftyp)
        out.write(new_mdat)
        out.write(moov)
    
    print(f"[+] Output: {output_file}")
    print(f"[+] Size: {len(ftyp) + len(new_mdat) + len(moov):,} bytes")
    
    return True

def main():
    # Find all .stems files in stems folder
    stems_dir = Path('stems')
    stems_files = list(stems_dir.glob('*.stems'))
    
    if not stems_files:
        print("[!] No .stems files found in stems/ folder")
        return
    
    print("=" * 70)
    print("STEMS FILE DECRYPTION")
    print("=" * 70)
    print()
    
    for stems_file in stems_files:
        # Find corresponding .keys file
        keys_file = stems_file.with_suffix('.keys')
        
        if not keys_file.exists():
            print(f"[!] No keys file found for {stems_file.name}")
            print(f"    Expected: {keys_file.name}")
            continue
        
        # Output file name
        output_file = stems_file.stem + '_decrypted.m4a'
        
        print(f"Processing: {stems_file.name}")
        print()
        
        try:
            decrypt_stems(str(stems_file), str(keys_file), output_file)
            print()
            print(f"✓ Success! Test with: ffprobe {output_file}")
            print()
        except Exception as e:
            print(f"✗ Error: {e}")
            print()
        
        print("-" * 70)
        print()
    
    print("=" * 70)
    print("DONE!")
    print("=" * 70)

if __name__ == '__main__':
    main()
