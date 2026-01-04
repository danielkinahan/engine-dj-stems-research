#!/usr/bin/env python3
"""
Parse packets_hex.txt and extract XOR keys for each packet.
"""

import re
import struct

def parse_packets_from_hex_file(filename):
    """Parse the hex dump output to extract packet data."""
    with open(filename, 'r') as f:
        content = f.read()
    
    packets = []
    
    # Find each packet section
    packet_sections = re.findall(r'=== PACKET (\d+) ===\s+SIZE: (\d+)\s+HEX:(.*?)(?=\n=== PACKET|\Z)', content, re.DOTALL)
    
    for packet_num, size_str, hex_section in packet_sections:
        size = int(size_str)
        
        # Extract hex bytes from the hexdump format
        hex_lines = re.findall(r'[0-9a-f]+\s+([0-9a-f\s]+?)\s+[|.]', hex_section, re.IGNORECASE)
        
        hex_bytes = []
        for line in hex_lines:
            # Parse hex bytes from format like "de 04 00 4c 61 76 63 35 38 2e 31 33 34 2e 31 30"
            bytes_in_line = line.strip().split()
            for byte_str in bytes_in_line:
                if len(byte_str) == 2:
                    hex_bytes.append(byte_str)
        
        packet_data = bytes.fromhex(''.join(hex_bytes))
        packets.append({
            'id': int(packet_num),
            'size': size,
            'data': packet_data
        })
        
        print(f"Parsed Packet {packet_num}: {len(packet_data)} bytes (expected {size})")
    
    return packets

def extract_keys_from_packets(packets, stems_file):
    """Extract XOR keys by comparing unencrypted packets with encrypted file."""
    print(f"\nLoading encrypted file: {stems_file}")
    
    with open(stems_file, 'rb') as f:
        encrypted_data = f.read()
    
    # Find mdat
    mdat_pos = encrypted_data.find(b'mdat')
    aac_start = mdat_pos - 4
    mdat_size = struct.unpack('>I', encrypted_data[aac_start:aac_start+4])[0]
    aac_offset = aac_start + 8
    aac_data = encrypted_data[aac_offset:aac_offset + mdat_size]
    
    print(f"AAC data starts at offset: 0x{aac_offset:X}")
    print(f"AAC data size: {len(aac_data)} bytes\n")
    
    # Extract keys
    keys = []
    current_offset = 0
    
    for packet in packets:
        packet_id = packet['id']
        unencrypted = packet['data']
        size = len(unencrypted)
        
        print(f"{'='*70}")
        print(f"Packet #{packet_id} (offset 0x{current_offset:X}, size {size} bytes)")
        print(f"{'='*70}")
        
        # Get encrypted data at this offset
        encrypted = aac_data[current_offset:current_offset + size]
        
        if len(encrypted) < size:
            print(f"WARNING: Not enough encrypted data ({len(encrypted)} bytes)")
            break
        
        # XOR to get key
        key = bytes(u ^ e for u, e in zip(unencrypted, encrypted))
        keys.append({
            'packet_id': packet_id,
            'offset': current_offset,
            'size': size,
            'key': key
        })
        
        # Show first 128 bytes of key
        print(f"\nKey (first 128 bytes):")
        key_sample = key[:128]
        for i in range(0, len(key_sample), 16):
            hex_part = ' '.join(f'{b:02x}' for b in key_sample[i:i+16])
            print(f"  {i:04x}: {hex_part}")
        
        # Verify decryption works
        decrypted = bytes(e ^ k for e, k in zip(encrypted[:128], key[:128]))
        if decrypted[:20] == unencrypted[:20]:
            print("\n✓ Key verified - decryption works!")
        else:
            print("\n✗ Key verification failed!")
        
        current_offset += size
    
    return keys

def analyze_key_pattern(keys):
    """Analyze keys to find the pattern."""
    print(f"\n{'='*70}")
    print("KEY PATTERN ANALYSIS")
    print(f"{'='*70}\n")
    
    if len(keys) < 2:
        print("Need at least 2 keys to analyze pattern")
        return
    
    print(f"Extracted {len(keys)} keys\n")
    
    # Compare first 128 bytes of each key
    print("Comparing first 128 bytes of each key:\n")
    
    key_samples = [k['key'][:128] for k in keys]
    
    # Check if keys are identical
    all_same = all(k == key_samples[0] for k in key_samples)
    if all_same:
        print("✓ All keys are IDENTICAL (first 128 bytes)")
        print("  Pattern: Simple repeating 128-byte key")
    else:
        print("✗ Keys are DIFFERENT")
        
        # Check for patterns
        print("\nLooking for patterns...")
        
        # Check if keys differ by simple increment
        diffs = []
        for i in range(1, len(key_samples)):
            diff = bytes(a ^ b for a, b in zip(key_samples[0], key_samples[i]))
            diffs.append(diff)
            
            # Count different bytes
            diff_count = sum(1 for b in diff if b != 0)
            print(f"  Key {i+1} vs Key 1: {diff_count}/128 bytes differ ({diff_count*100/128:.1f}%)")
        
        # Check if difference is constant (stream cipher with counter)
        if len(diffs) > 1:
            print("\nChecking if XOR differences follow a pattern...")
            # This would need more sophisticated analysis
    
    print(f"\n{'='*70}")
    print("CONCLUSION")
    print(f"{'='*70}")
    print("If keys are different, they're likely generated using:")
    print("  - Frame index/counter")
    print("  - Hash function (SHA256, MD5)")
    print("  - PRNG seeded with UUID + frame_number")
    print("\nTo find the exact algorithm, need to:")
    print("  1. Search Ghidra for key generation function")
    print("  2. Look for crypto library calls (OpenSSL)")
    print("  3. Check for patterns in key bytes")

# Main execution
if __name__ == '__main__':
    print("Parsing packets from packets_hex.txt...")
    packets = parse_packets_from_hex_file('packets_hex.txt')
    
    if not packets:
        print("ERROR: No packets found in file!")
        exit(1)
    
    print(f"\nFound {len(packets)} packets\n")
    
    # Use the newly generated stems file from the capture
    stems_file = 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems'
    
    keys = extract_keys_from_packets(packets, stems_file)
    
    if keys:
        analyze_key_pattern(keys)
        
        # Save keys to file for further analysis
        print(f"\n{'='*70}")
        print("Saving keys to keys_extracted.txt...")
        with open('keys_extracted.txt', 'w') as f:
            for k in keys:
                f.write(f"Packet {k['packet_id']} (offset 0x{k['offset']:X}):\n")
                key_hex = k['key'][:128].hex(' ')
                f.write(f"{key_hex}\n\n")
        print("✓ Saved!")
