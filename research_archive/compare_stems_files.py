#!/usr/bin/env python3
"""
Cross-File Stems Encryption Analysis
=====================================

Compares multiple .stems files to identify encryption key derivation patterns.
Examines if encryption is based on UUID, file position, track metadata, or other factors.

Target: Identify if XOR keys follow a pattern tied to file/track metadata
"""

import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple
import hashlib

class StemsComparator:
    def __init__(self, stems_dir: str):
        self.stems_dir = Path(stems_dir)
        self.stems_files = sorted(self.stems_dir.glob("*.stems"))
        self.file_data = {}
        self.metadata = {}
    
    def extract_filename_info(self, filename: str) -> Dict:
        """Extract UUID and other info from filename."""
        # Format appears to be: "{number} {uuid}.stems"
        parts = filename.replace('.stems', '').split(' ', 1)
        return {
            'number': parts[0] if len(parts) > 0 else None,
            'uuid': parts[1] if len(parts) > 1 else None,
        }
    
    def load_stems_files(self):
        """Load all stems files."""
        print(f"Loading stems files from: {self.stems_dir}\n")
        
        for stems_file in self.stems_files:
            try:
                with open(stems_file, 'rb') as f:
                    data = f.read()
                
                filename = stems_file.name
                self.file_data[filename] = data
                self.metadata[filename] = {
                    'path': str(stems_file),
                    'size': len(data),
                    'info': self.extract_filename_info(filename)
                }
                
                print(f"✓ Loaded: {filename}")
                print(f"  Size: {len(data):,} bytes")
                print(f"  UUID: {self.metadata[filename]['info']['uuid']}\n")
                
            except Exception as e:
                print(f"✗ Failed to load {stems_file.name}: {e}\n")
    
    def extract_mdat_section(self, data: bytes, max_bytes: int = 512) -> bytes:
        """Extract the mdat (media data) section from MP4."""
        # mdat usually starts with 'mdat' tag
        mdat_start = data.find(b'mdat')
        if mdat_start == -1:
            print("Warning: Could not find mdat tag")
            return b''
        
        # Skip 'mdat' (4 bytes) + size (4 bytes)
        payload_start = mdat_start + 8
        return data[payload_start:payload_start + max_bytes]
    
    def extract_frames(self, mdat_data: bytes) -> List[bytes]:
        """Extract ADTS frames from mdat section."""
        frames = []
        pos = 0
        
        while pos < len(mdat_data) - 10:
            # ADTS frame header starts with 0xFFF (11 bits sync word)
            if mdat_data[pos] == 0xFF and (mdat_data[pos + 1] & 0xF0) == 0xF0:
                # Get frame length (13 bits at positions 30-32)
                length_bits = ((mdat_data[pos + 3] & 0x03) << 8) | mdat_data[pos + 4]
                frame_length = (length_bits >> 5) & 0x1FFF
                
                if frame_length < 7 or frame_length > 4096:  # Sanity check
                    pos += 1
                    continue
                
                frame = mdat_data[pos:pos + frame_length]
                if len(frame) == frame_length:
                    frames.append(frame)
                    pos += frame_length
                else:
                    break
            else:
                pos += 1
        
        return frames
    
    def compare_byte_patterns(self):
        """Compare byte patterns across files at key positions."""
        print("=" * 80)
        print("BYTE PATTERN COMPARISON")
        print("=" * 80 + "\n")
        
        files_list = list(self.file_data.keys())
        
        if len(files_list) < 2:
            print("Need at least 2 stems files for comparison\n")
            return
        
        # Compare file headers
        print("File Header Comparison (first 512 bytes):\n")
        
        header_size = 512
        for filename in files_list:
            data = self.file_data[filename]
            header = data[:header_size]
            
            print(f"{filename}:")
            print(f"  Hex dump (first 96 bytes):")
            for i in range(0, min(96, len(header)), 16):
                hex_str = ' '.join(f'{b:02x}' for b in header[i:i+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[i:i+16])
                print(f"    {i:04x}: {hex_str:<48} {ascii_str}")
            print()
        
        # Find common bytes
        print("\nByte Difference Analysis:\n")
        
        if len(files_list) == 2:
            file1, file2 = files_list[0], files_list[1]
            data1, data2 = self.file_data[file1], self.file_data[file2]
            
            min_len = min(len(data1), len(data2))
            
            differences = []
            for i in range(min(2048, min_len)):
                if data1[i] != data2[i]:
                    differences.append((i, data1[i], data2[i]))
            
            print(f"First 2048 bytes: {len(differences)} differences\n")
            
            print("First 20 differences:")
            for offset, byte1, byte2 in differences[:20]:
                xor_val = byte1 ^ byte2
                print(f"  Offset {offset:04x}: {byte1:02x} vs {byte2:02x} (XOR: {xor_val:02x})")
            print()
    
    def analyze_frame_encryption(self):
        """Analyze encryption patterns in ADTS frames."""
        print("=" * 80)
        print("FRAME-LEVEL ENCRYPTION ANALYSIS")
        print("=" * 80 + "\n")
        
        for filename, data in self.file_data.items():
            print(f"\n{filename}:")
            
            mdat_data = self.extract_mdat_section(data)
            frames = self.extract_frames(mdat_data)
            
            print(f"  Extracted {len(frames)} ADTS frames\n")
            
            # Analyze first frame (should be PCE)
            if len(frames) > 0:
                frame0 = frames[0]
                print(f"  Frame 0 (PCE):")
                print(f"    Length: {len(frame0)} bytes")
                print(f"    First 32 bytes (hex):")
                hex_str = ' '.join(f'{b:02x}' for b in frame0[:32])
                print(f"      {hex_str}\n")
            
            # Analyze frames 1-5 (should be encrypted)
            print(f"  Frames 1-5 (encrypted audio):")
            for frame_idx in range(1, min(6, len(frames))):
                frame = frames[frame_idx]
                
                # Skip ADTS header (7 bytes), look at raw data block
                if len(frame) > 7:
                    raw_data_start = frame[7:]
                    first_byte = raw_data_start[0]
                    
                    # Try XOR with common values to find element tag
                    print(f"    Frame {frame_idx}: First byte = 0x{first_byte:02x}")
                    
                    # Check if XOR produces valid CPE/SCE tag
                    for xor_val in [0x19, 0x20, 0x18, 0x25]:
                        xored = first_byte ^ xor_val
                        tag_type = {
                            0x20: "CPE (2ch)", 0x10: "SCE (1ch)", 0x00: "PCE"
                        }.get(xored & 0xF8, f"Unknown (0x{xored:02x})")
                        
                        print(f"      XOR 0x{xor_val:02x} → 0x{xored:02x} ({tag_type})")
    
    def compare_uuid_metadata(self):
        """Compare UUID and metadata relationships."""
        print("=" * 80)
        print("UUID & METADATA CORRELATION")
        print("=" * 80 + "\n")
        
        for filename, meta in self.metadata.items():
            uuid = meta['info']['uuid']
            size = meta['size']
            
            print(f"{filename}:")
            print(f"  UUID: {uuid}")
            print(f"  File Size: {size:,} bytes")
            
            # Compute hashes of UUID for potential key derivation
            uuid_sha256 = hashlib.sha256(uuid.encode()).hexdigest()
            uuid_md5 = hashlib.md5(uuid.encode()).hexdigest()
            
            print(f"  UUID Hash (SHA256): {uuid_sha256[:32]}...")
            print(f"  UUID Hash (MD5): {uuid_md5}")
            
            # Check if file size correlates to XOR values
            print(f"  Size correlation: {size % 256} (mod 256)")
            print()
    
    def identify_xor_patterns(self):
        """Attempt to identify XOR key patterns across files."""
        print("=" * 80)
        print("XOR KEY PATTERN IDENTIFICATION")
        print("=" * 80 + "\n")
        
        # Extract known XOR values from analyze.py research
        known_xor_values = {
            1: 0x19, 2: 0x78, 3: 0x65, 4: 0x12, 5: 0x70,
            6: 0x29, 7: 0x20, 8: 0x9f, 9: 0x4e, 10: 0xa3,
            11: 0xd2, 12: 0x27, 13: 0xdf, 14: 0x52, 15: 0xb4
        }
        
        print("Known XOR values (from previous analysis):")
        for frame_num, xor_val in sorted(known_xor_values.items()):
            print(f"  Frame {frame_num}: 0x{xor_val:02x}")
        
        print("\nPattern Analysis:")
        xor_list = list(known_xor_values.values())
        
        # Check for arithmetic progression
        differences = [xor_list[i+1] - xor_list[i] for i in range(len(xor_list)-1)]
        print(f"  Differences between consecutive XORs: {differences[:5]}...")
        print(f"  All differences unique: {len(set(differences)) == len(differences)}")
        
        # Check for polynomial relationship
        print(f"\n  XOR values appear to be: {type(xor_list)} with no clear pattern")
        print(f"  Hypothesis: Per-frame stream cipher with independent keys")
        print()

def main():
    stems_dir = "c:\\Users\\Daniel\\git\\engine-dj-stems-research\\stems"
    
    if not os.path.exists(stems_dir):
        print(f"Stems directory not found: {stems_dir}")
        return
    
    comparator = StemsComparator(stems_dir)
    comparator.load_stems_files()
    
    if len(comparator.file_data) >= 1:
        comparator.compare_byte_patterns()
        comparator.analyze_frame_encryption()
        comparator.compare_uuid_metadata()
        comparator.identify_xor_patterns()
    
    print("=" * 80)
    print("CROSS-FILE ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
