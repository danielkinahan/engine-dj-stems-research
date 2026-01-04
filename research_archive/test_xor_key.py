#!/usr/bin/env python3
"""
Test decryption using the extracted XOR key on existing .stems file.
"""

import struct

# The XOR key we extracted from Frame 1
XOR_KEY_FRAME1 = bytes([
    0x3a, 0x81, 0xb0, 0x58, 0x70, 0x0c, 0x86, 0x0e, 0xd3, 0xb8, 0xef, 0xe2, 0xdf, 0xb0, 0x7b, 0x61,
    0x02, 0x74, 0x8c, 0xc3, 0x4a, 0xf8, 0x60, 0x4e, 0x2e, 0x0b, 0x74, 0x81, 0x5f, 0x13, 0x5e, 0x6c,
    0x0c, 0xb1, 0x58, 0x44, 0x0f, 0x92, 0x6c, 0xfa, 0x25, 0xc7, 0x8f, 0x16, 0x1e, 0x3a, 0xc3, 0x41,
    0xad, 0xe5, 0x35, 0xc0, 0x83, 0x1c, 0xf6, 0x86, 0x18, 0xf9, 0x57, 0xd3, 0x0f, 0x00, 0x03, 0xe1,
    0x45, 0xfd, 0xa1, 0x3e, 0x8c, 0xbd, 0xbd, 0x9c, 0x93, 0x2d, 0x88, 0x29, 0x69, 0x6d, 0x28, 0x62,
    0x77, 0x00, 0xf8, 0x15, 0xf8, 0x9f, 0x76, 0x86, 0x35, 0x18, 0x92, 0xe4, 0x31, 0x21, 0xa9, 0x35,
    0x52, 0x6e, 0x42, 0x3e, 0x7b, 0x6e, 0xb0, 0xb3, 0x52, 0x9d, 0x56, 0xfa, 0xd6, 0xaf, 0xc6, 0x90,
    0xc1, 0x2b, 0xad, 0xa3, 0x50, 0xf0, 0xcb, 0xef, 0xb6, 0xc4, 0x4f, 0xf8, 0x99, 0xcc, 0x97, 0x39,
])

def test_decrypt_stems(stems_file):
    """Test if our XOR key works on an existing .stems file."""
    print(f"\n{'='*70}")
    print(f"Testing: {stems_file}")
    print(f"{'='*70}")
    
    with open(stems_file, 'rb') as f:
        data = f.read()
    
    # Find mdat atom
    mdat_pos = data.find(b'mdat')
    if mdat_pos == -1:
        print("No mdat atom found!")
        return
    
    aac_start = mdat_pos - 4
    mdat_size = struct.unpack('>I', data[aac_start:aac_start+4])[0]
    aac_data = data[aac_start + 8:aac_start + mdat_size]
    
    print(f"AAC data starts at: 0x{aac_start + 8:X}")
    print(f"AAC data size: {len(aac_data)} bytes")
    
    # Try to decrypt first 128 bytes with our key
    encrypted_first_128 = aac_data[:128]
    
    print("\nFirst 128 bytes (ENCRYPTED):")
    for i in range(0, 64, 16):
        hex_part = ' '.join(f'{b:02x}' for b in encrypted_first_128[i:i+16])
        print(f"  {i:04x}: {hex_part}")
    
    # XOR decrypt
    decrypted = bytes(e ^ k for e, k in zip(encrypted_first_128, XOR_KEY_FRAME1))
    
    print("\nFirst 128 bytes (DECRYPTED with extracted key):")
    for i in range(0, 64, 16):
        hex_part = ' '.join(f'{b:02x}' for b in decrypted[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decrypted[i:i+16])
        print(f"  {i:04x}: {hex_part}  {ascii_part}")
    
    # Check if it looks like valid AAC
    if decrypted[0:4] == b'\xde\x04\x00L':  # Match the Frida capture
        print("\n✓✓✓ KEY WORKS! First bytes match!")
        print("✓✓✓ This is likely the UNIVERSAL key or a repeating pattern!")
    elif b'Lavc' in decrypted:
        print("\n✓ Found 'Lavc' string - likely FFmpeg encoder signature!")
        print("✓ Key might work but with slight offset")
    else:
        print("\n✗ Decryption doesn't match - key is FILE-SPECIFIC")
        print("✗ Keys are derived per-file (from UUID or similar)")

# Test on both sample files
stems_files = [
    'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems',
    'stems/2 0f7da717-a4c6-46be-994e-eca19516836c.stems'
]

for stems_file in stems_files:
    try:
        test_decrypt_stems(stems_file)
    except FileNotFoundError:
        print(f"File not found: {stems_file}")
    except Exception as e:
        print(f"Error: {e}")

print("\n" + "="*70)
print("ANALYSIS COMPLETE")
print("="*70)
