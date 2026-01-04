#!/usr/bin/env python3
"""
Decrypt entire .stems file using the extracted 128-byte XOR key (repeating).
"""

import struct
import sys

# The 128-byte XOR key extracted from Frame 1
XOR_KEY = bytes([
    0x3a, 0x81, 0xb0, 0x58, 0x70, 0x0c, 0x86, 0x0e, 0xd3, 0xb8, 0xef, 0xe2, 0xdf, 0xb0, 0x7b, 0x61,
    0x02, 0x74, 0x8c, 0xc3, 0x4a, 0xf8, 0x60, 0x4e, 0x2e, 0x0b, 0x74, 0x81, 0x5f, 0x13, 0x5e, 0x6c,
    0x0c, 0xb1, 0x58, 0x44, 0x0f, 0x92, 0x6c, 0xfa, 0x25, 0xc7, 0x8f, 0x16, 0x1e, 0x3a, 0xc3, 0x41,
    0xad, 0xe5, 0x35, 0xc0, 0x83, 0x1c, 0xf6, 0x86, 0x18, 0xf9, 0x57, 0xd3, 0x0f, 0x00, 0x03, 0xe1,
    0x45, 0xfd, 0xa1, 0x3e, 0x8c, 0xbd, 0xbd, 0x9c, 0x93, 0x2d, 0x88, 0x29, 0x69, 0x6d, 0x28, 0x62,
    0x77, 0x00, 0xf8, 0x15, 0xf8, 0x9f, 0x76, 0x86, 0x35, 0x18, 0x92, 0xe4, 0x31, 0x21, 0xa9, 0x35,
    0x52, 0x6e, 0x42, 0x3e, 0x7b, 0x6e, 0xb0, 0xb3, 0x52, 0x9d, 0x56, 0xfa, 0xd6, 0xaf, 0xc6, 0x90,
    0xc1, 0x2b, 0xad, 0xa3, 0x50, 0xf0, 0xcb, 0xef, 0xb6, 0xc4, 0x4f, 0xf8, 0x99, 0xcc, 0x97, 0x39,
])

def decrypt_stems(input_file, output_file):
    """
    Decrypt a .stems file by XORing the mdat AAC data with the repeating 128-byte key.
    """
    print(f"Decrypting: {input_file}")
    print(f"Output: {output_file}")
    
    # Read the file
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())
    
    # Find mdat atom
    mdat_pos = data.find(b'mdat')
    if mdat_pos == -1:
        print("ERROR: No mdat atom found!")
        return False
    
    # Calculate AAC data location
    aac_start = mdat_pos - 4
    mdat_size = struct.unpack('>I', data[aac_start:aac_start+4])[0]
    aac_data_offset = aac_start + 8
    aac_data_end = aac_start + mdat_size
    
    print(f"\nmdat atom at: 0x{mdat_pos:X}")
    print(f"AAC data: 0x{aac_data_offset:X} - 0x{aac_data_end:X}")
    print(f"AAC size: {aac_data_end - aac_data_offset} bytes")
    
    # Decrypt by XORing with repeating key
    print("\nDecrypting...")
    for i in range(aac_data_offset, aac_data_end):
        key_byte = XOR_KEY[(i - aac_data_offset) % len(XOR_KEY)]
        data[i] ^= key_byte
    
    # Write decrypted file
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print(f"\n✓ Decrypted file saved: {output_file}")
    
    # Verify first frame looks valid
    print("\nVerifying first 64 bytes of decrypted AAC:")
    decrypted_aac = data[aac_data_offset:aac_data_offset+64]
    for i in range(0, 64, 16):
        hex_part = ' '.join(f'{b:02x}' for b in decrypted_aac[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted_aac[i:i+16])
        print(f"  {i:04x}: {hex_part}  {ascii_part}")
    
    # Check for ADTS sync
    if decrypted_aac[0] == 0xFF and (decrypted_aac[1] & 0xF0) == 0xF0:
        print("\n✗ Starts with ADTS sync (0xFFF) - but we expect Lavc signature first")
        print("   Key might be offset-specific")
    elif b'Lavc' in decrypted_aac[:20]:
        print("\n✓ Found 'Lavc' signature - FFmpeg encoded AAC")
        print("✓ Decryption successful!")
    
    return True

if __name__ == '__main__':
    # Test on sample file
    input_file = 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems'
    output_file = 'stems/1_DECRYPTED.m4a'
    
    if decrypt_stems(input_file, output_file):
        print("\n" + "="*70)
        print("SUCCESS! Now test playback:")
        print(f"  ffplay \"{output_file}\"")
        print("Or:")
        print(f"  ffmpeg -i \"{output_file}\" -map 0:a:0 -ac 2 drums.wav")
        print(f"  ffmpeg -i \"{output_file}\" -map 0:a:1 -ac 2 bass.wav")
        print(f"  ffmpeg -i \"{output_file}\" -map 0:a:2 -ac 2 melody.wav")
        print(f"  ffmpeg -i \"{output_file}\" -map 0:a:3 -ac 2 vocals.wav")
        print("="*70)
