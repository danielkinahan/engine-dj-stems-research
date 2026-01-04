#!/usr/bin/env python3
"""
Analyze if XOR key changes per frame by checking ADTS sync patterns.
"""

import struct

def find_adts_sync_in_encrypted(stems_file):
    """
    In encrypted data, ADTS sync (0xFF 0xFX) will be XORed.
    If key repeats, we should see same XOR'd pattern every frame.
    """
    print(f"Analyzing: {stems_file}\n")
    
    with open(stems_file, 'rb') as f:
        data = f.read()
    
    # Find mdat
    mdat_pos = data.find(b'mdat')
    aac_start = mdat_pos - 4
    mdat_size = struct.unpack('>I', data[aac_start:aac_start+4])[0]
    aac_data = data[aac_start + 8:aac_start + mdat_size]
    
    print(f"Searching for ADTS sync patterns in encrypted data...")
    print(f"If key repeats, every frame should start with same encrypted bytes\n")
    
    # Expected: ADTS frames start with 0xFF 0xFX
    # After XOR with our key: 0xFF ^ 0x3a = 0xC5, 0xF6 ^ 0x81 = 0x77
    # So encrypted frames should start with 0xC5 0x77 if key repeats
    
    # But wait - the first frame in our capture didn't start with 0xFF!
    # It started with 0xde 04 00 4c (Lavc signature)
    # This means Frame 0 might be special (metadata frame)
    
    # Let's find what looks like frame boundaries
    print("First 10 potential frame starts:")
    print("(Looking for repeating 2-byte patterns that might be encrypted 0xFF 0xFX)\n")
    
    frame_starts = []
    # Scan for patterns
    for i in range(0, min(50000, len(aac_data) - 2)):
        if i > 0 and i % 1000 == 0:
            # Check if we see consistent patterns at regular intervals
            pass
        
        # Just show first 20 occurrences of each unique 2-byte pattern
        first_two = aac_data[i:i+2]
        if i < 10000 and i % 500 == 0:  # Sample every 500 bytes
            frame_starts.append((i, first_two.hex()))
    
    for offset, pattern in frame_starts[:20]:
        print(f"  Offset 0x{offset:04X}: {pattern}")
    
    print("\n" + "="*70)
    print("Let's try decrypting with offset-based keys...")
    print("="*70)

# Run analysis
find_adts_sync_in_encrypted('stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems')

print("\nThe issue: Frame 1 in our capture was 1520 bytes.")
print("If the key changes PER FRAME, we need to extract keys for each frame.")
print("\nBetter approach: Check if it's a CONTINUOUS stream cipher")
print("where the key is generated based on byte position, not frame number.")
