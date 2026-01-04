#!/usr/bin/env python3
"""
Analyze .stems files to find XOR key patterns by comparing frames.
We know Frame 0 is unencrypted (valid PCE). Frames 1+ are encrypted.
"""

import struct
import os

def find_adts_frames(data):
    """Find all ADTS frame positions in the data."""
    frames = []
    pos = 0
    
    while pos < len(data) - 7:
        # ADTS sync word: 0xFFF (12 bits)
        if data[pos] == 0xFF and (data[pos + 1] & 0xF0) == 0xF0:
            # Parse ADTS header
            frame_length = ((data[pos + 3] & 0x03) << 11) | \
                          (data[pos + 4] << 3) | \
                          ((data[pos + 5] & 0xE0) >> 5)
            
            if frame_length > 7 and pos + frame_length <= len(data):
                frames.append({
                    'offset': pos,
                    'length': frame_length,
                    'data': data[pos:pos + frame_length]
                })
                pos += frame_length
            else:
                pos += 1
        else:
            pos += 1
    
    return frames

def analyze_frame_encryption(stems_file):
    """Analyze encryption pattern in a .stems file."""
    print(f"\n{'='*70}")
    print(f"Analyzing: {stems_file}")
    print(f"{'='*70}")
    
    with open(stems_file, 'rb') as f:
        data = f.read()
    
    # Find mdat atom (where AAC data starts)
    mdat_pos = data.find(b'mdat')
    if mdat_pos == -1:
        print("No mdat atom found!")
        return
    
    # AAC data starts after 'mdat' + size (8 bytes total)
    aac_start = mdat_pos - 4  # mdat header is: [size:4][mdat:4]
    mdat_size = struct.unpack('>I', data[aac_start:aac_start+4])[0]
    aac_data = data[aac_start + 8:aac_start + mdat_size]
    
    print(f"\nmdat atom at offset: 0x{mdat_pos:X}")
    print(f"AAC data starts at: 0x{aac_start + 8:X}")
    print(f"AAC data size: {len(aac_data)} bytes")
    
    # Find ADTS frames
    frames = find_adts_frames(aac_data)
    print(f"\nFound {len(frames)} ADTS frames")
    
    if len(frames) == 0:
        print("\nNo valid ADTS frames found - data is heavily encrypted!")
        print("First 64 bytes of AAC data:")
        print_hex(aac_data[:64])
        return
    
    # Analyze first few frames
    print("\n" + "="*70)
    print("FRAME ANALYSIS")
    print("="*70)
    
    for i, frame in enumerate(frames[:5]):
        print(f"\n--- Frame {i} ---")
        print(f"Offset: 0x{frame['offset']:X}")
        print(f"Length: {frame['length']} bytes")
        
        # Show first 32 bytes
        frame_data = frame['data']
        print("First 32 bytes:")
        print_hex(frame_data[:32])
        
        # Check element type (byte 7 after sync)
        if len(frame_data) > 7:
            element_tag = (frame_data[7] >> 5) & 0x07
            print(f"Element tag: 0x{element_tag:X}", end="")
            
            element_names = {
                0: "SCE (Single Channel Element)",
                1: "CPE (Channel Pair Element)", 
                2: "CCE (Coupling Channel Element)",
                3: "LFE (LF Enhancement Element)",
                4: "DSE (Data Stream Element)",
                5: "PCE (Program Config Element)",
                6: "FIL (Fill Element)",
                7: "END (Terminator)"
            }
            
            if element_tag in element_names:
                print(f" - {element_names[element_tag]}")
            else:
                print(" - UNKNOWN/INVALID")
            
            # If invalid element, this frame is likely encrypted
            if element_tag not in [0, 1, 2, 3, 4, 5, 6, 7]:
                print("⚠️  INVALID ELEMENT - This frame is ENCRYPTED")

def print_hex(data):
    """Print data as hex dump."""
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"  {i:04X}: {hex_part:<48}  {ascii_part}")

def compare_frames_for_xor_key(file1, file2):
    """Compare corresponding frames from two files to find XOR patterns."""
    print(f"\n{'='*70}")
    print("CROSS-FILE XOR ANALYSIS")
    print(f"{'='*70}")
    
    # Read both files
    with open(file1, 'rb') as f:
        data1 = f.read()
    with open(file2, 'rb') as f:
        data2 = f.read()
    
    # Find mdat in both
    mdat1 = data1.find(b'mdat')
    mdat2 = data2.find(b'mdat')
    
    if mdat1 == -1 or mdat2 == -1:
        print("Could not find mdat in both files")
        return
    
    # Get AAC data
    aac1_start = mdat1 - 4
    aac2_start = mdat2 - 4
    
    mdat1_size = struct.unpack('>I', data1[aac1_start:aac1_start+4])[0]
    mdat2_size = struct.unpack('>I', data2[aac2_start:aac2_start+4])[0]
    
    aac1 = data1[aac1_start + 8:aac1_start + mdat1_size]
    aac2 = data2[aac2_start + 8:aac2_start + mdat2_size]
    
    print(f"\nFile 1 AAC size: {len(aac1)} bytes")
    print(f"File 2 AAC size: {len(aac2)} bytes")
    
    # Compare first 512 bytes (likely covers first encrypted frame)
    compare_size = min(512, len(aac1), len(aac2))
    
    print(f"\nXOR difference in first {compare_size} bytes:")
    print("(If XOR keys are different, this shows the pattern)")
    
    xor_diffs = []
    for i in range(compare_size):
        xor_val = aac1[i] ^ aac2[i]
        xor_diffs.append(xor_val)
    
    # Print XOR differences
    for i in range(0, compare_size, 16):
        xor_part = ' '.join(f'{b:02X}' for b in xor_diffs[i:i+16])
        print(f"  {i:04X}: {xor_part}")
    
    # Check if there's a repeating pattern
    print("\nLooking for repeating patterns in XOR differences...")
    for pattern_len in [16, 32, 64, 128, 256]:
        if pattern_len * 2 <= len(xor_diffs):
            pattern1 = xor_diffs[:pattern_len]
            pattern2 = xor_diffs[pattern_len:pattern_len*2]
            if pattern1 == pattern2:
                print(f"✓ Found repeating {pattern_len}-byte pattern!")
                break
    else:
        print("✗ No simple repeating pattern found")

# Main execution
if __name__ == '__main__':
    stems_files = [
        'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems',
        'stems/2 0f7da717-a4c6-46be-994e-eca19516836c.stems'
    ]
    
    # Analyze each file
    for stems_file in stems_files:
        if os.path.exists(stems_file):
            analyze_frame_encryption(stems_file)
    
    # Compare files
    if all(os.path.exists(f) for f in stems_files):
        compare_frames_for_xor_key(stems_files[0], stems_files[1])
    
    print("\n" + "="*70)
    print("Analysis complete!")
    print("="*70)
