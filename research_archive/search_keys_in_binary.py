#!/usr/bin/env python3
"""
Search for extracted keys in Engine DJ binary
"""

import os

exe_path = r"C:\Program Files\Engine DJ\Engine DJ.exe"

# First 16 bytes of our extracted keys
key1_hex = "3a81b058700c860ed3b8efe2dfb07b61"
key1_bytes = bytes.fromhex(key1_hex)

print(f"[*] Searching for first key in Engine DJ.exe")
print(f"[*] Key: {key1_hex}")
print(f"[*] Binary: {exe_path}\n")

if not os.path.exists(exe_path):
    print(f"[!] Binary not found at {exe_path}")
    exit(1)

try:
    with open(exe_path, 'rb') as f:
        binary_data = f.read()
    
    # Search for exact key bytes
    offset = binary_data.find(key1_bytes)
    
    if offset >= 0:
        print(f"[+] FOUND at offset: 0x{offset:x}")
        print(f"    Relative to PE base (typically 0x400000): 0x{offset + 0x400000:x}")
        
        # Show context
        start = max(0, offset - 32)
        end = min(len(binary_data), offset + len(key1_bytes) + 32)
        context = binary_data[start:end]
        
        print(f"\n[+] Context (±32 bytes):")
        for i, byte in enumerate(context):
            if i == offset - start:
                print(f"\n>>> {' '.join(f'{b:02x}' for b in context[i:i+16])}")
                print("    " + " ".join("--" if j == offset - start else "  " for j in range(len(context[i:i+16]))))
                i += 16
            else:
                if i % 16 == 0:
                    print(f"    {' '.join(f'{b:02x}' for b in context[i:min(i+16, end-start)])}")
    else:
        print(f"[-] Key 1 NOT found in binary")
        
        # Try searching for shorter patterns
        print(f"\n[*] Trying to find patterns within key...")
        for pattern_len in [4, 8]:
            pattern = key1_bytes[:pattern_len]
            count = 0
            offset = 0
            while True:
                offset = binary_data.find(pattern, offset)
                if offset < 0:
                    break
                count += 1
                offset += 1
            print(f"    {pattern_len}-byte pattern 0x{pattern.hex()}: found {count} times")
            
except Exception as e:
    print(f"[!] Error: {e}")

print("\n[*] Analysis:")
print("    If key found:  Keys are hardcoded/stored in binary")
print("    If not found:  Keys are generated at runtime (not stored)")
