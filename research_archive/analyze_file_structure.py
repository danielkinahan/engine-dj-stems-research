#!/usr/bin/env python3
"""
Analyze the actual .stems file structure
"""

stems_file = "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"

with open(stems_file, 'rb') as f:
    data = f.read(1024)

print("[*] First 256 bytes of .stems file (as-is, no decryption):")
for i in range(0, min(256, len(data)), 16):
    hex_line = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_line = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f"  {i:04x}: {hex_line:<48} | {ascii_line}")

print("\n[*] Pattern analysis:")
print(f"  First 4 bytes: {' '.join(f'{b:02x}' for b in data[:4])} = {data[:4]}")
print(f"  First 8 bytes: {' '.join(f'{b:02x}' for b in data[:8])}")

# Check for common signatures
signatures = {
    b'ftyp': 'MP4 file type box',
    b'mdat': 'MP4 media data box',
    b'moov': 'MP4 movie metadata',
    b'Lavc': 'FFmpeg signature',
    b'ID3': 'ID3 tag',
    b'\xff\xfb': 'MP3 MPEG-1 Layer III sync',
    b'\xff\xfa': 'MP3 MPEG-2 Layer III sync',
    b'\xff\xf3': 'MP3 MPEG-2.5 Layer III sync',
    b'RIFF': 'WAV container',
    b'fLaC': 'FLAC audio',
}

print("\n[*] Searching for known signatures in first 4KB:")
full_chunk = data
for sig, desc in signatures.items():
    if sig in full_chunk:
        offset = full_chunk.find(sig)
        print(f"  [+] Found {desc} ({sig}) at offset 0x{offset:x}")
    
# Try to see if there's any repeating pattern
print("\n[*] Entropy analysis of first 256 bytes:")
byte_counts = {}
for b in data[:256]:
    byte_counts[b] = byte_counts.get(b, 0) + 1

common = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:10]
print("  Most common bytes:")
for byte, count in common:
    print(f"    0x{byte:02x}: {count} times")

# Calculate Shannon entropy
import math
entropy = 0
for count in byte_counts.values():
    p = count / 256
    if p > 0:
        entropy -= p * math.log2(p)
print(f"\n  Shannon Entropy: {entropy:.2f} bits/byte (8.0 = random, ~0 = repetitive)")

# Check if it looks encrypted (high entropy suggests encryption)
if entropy > 7.0:
    print("  [!] Very high entropy - likely encrypted data")
elif entropy < 3.0:
    print("  [!] Low entropy - likely structured/uncompressed data")
else:
    print("  [?] Medium entropy - could be compressed or encrypted")
