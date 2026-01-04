#!/usr/bin/env python3
"""
Search for XOR key pattern in Engine DJ binary

Known XOR values from frame analysis:
Frame 1: 0x19, Frame 2: 0x78, Frame 3: 0x65, Frame 4: 0x12, Frame 5: 0x70, etc.

If these are hardcoded, we'll find them in the binary.
"""

import os
import sys

def search_pattern_in_binary(binary_path, patterns):
    """
    Search for one or more byte patterns in a binary file
    
    Args:
        binary_path: Path to Engine DJ.exe
        patterns: List of byte patterns to search for
    
    Returns:
        List of matches with context
    """
    
    if not os.path.exists(binary_path):
        print(f"❌ File not found: {binary_path}")
        sys.exit(1)
    
    print(f"[*] Reading binary: {binary_path}")
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    print(f"[*] Binary size: {len(data):,} bytes ({len(data) / 1024 / 1024:.1f} MB)")
    
    all_matches = []
    
    for pattern_name, pattern_bytes in patterns:
        print(f"[*] Searching for: {pattern_name}...", end='', flush=True)
        
        matches = []
        pattern_len = len(pattern_bytes)
        
        # Use bytes.find() for faster searching
        start = 0
        while True:
            pos = data.find(pattern_bytes, start)
            if pos == -1:
                break
            matches.append(pos)
            start = pos + 1
        
        if matches:
            print(f" [FOUND] {len(matches)} match(es)")
            for offset in matches:
                # Get context around match
                start = max(0, offset - 16)
                end = min(len(data), offset + len(pattern_bytes) + 16)
                context = data[start:end]
                
                # Highlight the pattern in context
                rel_offset = offset - start
                before = context[:rel_offset].hex()
                pattern = context[rel_offset:rel_offset+pattern_len].hex()
                after = context[rel_offset+pattern_len:].hex()
                
                print(f"\n    Offset: 0x{offset:08X}")
                print(f"    Context: {before} [{pattern}] {after}")
                
                # Show surrounding 64 bytes for Ghidra navigation
                context_start = max(0, offset - 32)
                context_end = min(len(data), offset + len(pattern_bytes) + 32)
                context_full = data[context_start:context_end]
                print(f"    Full context (0x{context_start:08X}-0x{context_end:08X}):")
                hex_dump = ' '.join(f'{b:02x}' for b in context_full)
                print(f"      {hex_dump}")
                
                all_matches.append({
                    'pattern': pattern_name,
                    'offset': offset,
                    'context': context,
                    'context_start': context_start,
                    'context_end': context_end
                })
        else:
            print(f" [NOT FOUND]")
    
    return all_matches


def main():
    engine_dj_path = "C:\\Program Files\\Engine DJ\\Engine DJ.exe"
    
    print("=" * 80)
    print("Engine DJ XOR Key Pattern Search")
    print("=" * 80)
    
    # Patterns to search for
    patterns = [
        # Full sequence from frames 1-6
        ("XOR sequence (frames 1-6)", bytes([0x19, 0x78, 0x65, 0x12, 0x70, 0x29])),
        
        # Partial sequences (might be split)
        ("XOR sequence (frames 1-5)", bytes([0x19, 0x78, 0x65, 0x12, 0x70])),
        ("XOR sequence (frames 1-4)", bytes([0x19, 0x78, 0x65, 0x12])),
        ("XOR sequence (frames 1-3)", bytes([0x19, 0x78, 0x65])),
        
        # Individual values (might indicate a table)
        ("Single 0x19", bytes([0x19])),
        ("Single 0x78", bytes([0x78])),
        ("Single 0x65", bytes([0x65])),
        
        # UUID from database (might be used in key derivation)
        ("UUID prefix (0f7da717)", bytes([0x0f, 0x7d, 0xa7, 0x17])),
        
        # Common XOR key sizes (16, 24, 32 bytes)
        # These are harder to search without knowing exact keys, so skip for now
    ]
    
    matches = search_pattern_in_binary(engine_dj_path, patterns)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if matches:
        print(f"\n[SUCCESS] Found {len(matches)} match(es)!")
        print("\nNext steps:")
        print("1. Take note of the offset(s) above")
        print("2. Open Engine DJ.exe in Ghidra")
        print("3. Go → Address → Enter the hex offset (without 0x prefix)")
        print("4. Analyze the code around that location")
        print("5. Look for:")
        print("   - Arrays/tables of XOR values")
        print("   - Functions that use these values")
        print("   - How the values are indexed (frame number? offset?)")
        
        print("\n" + "=" * 80)
        print("MATCH DETAILS (for Ghidra)")
        print("=" * 80)
        for match in matches:
            print(f"\nPattern: {match['pattern']}")
            print(f"Offset: 0x{match['offset']:08X}")
            print(f"In Ghidra: Press 'G', enter: {match['offset']:X}")
    else:
        print("\n[NO MATCHES] Pattern not found in binary")
        print("\nThis could mean:")
        print("1. XOR keys are computed, not hardcoded")
        print("2. They're stored differently (obfuscated, compressed, etc.)")
        print("3. They're dynamically generated")
        print("\nNext approach: Search for key derivation functions in Ghidra")
        print("  - Look for hash functions (SHA256, MD5)")
        print("  - Look for UUID processing")
        print("  - Look for frame index calculations")


if __name__ == '__main__':
    main()
