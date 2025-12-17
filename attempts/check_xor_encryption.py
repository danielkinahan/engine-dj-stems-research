#!/usr/bin/env python3
"""
Check for XOR encryption patterns in Engine DJ stems AAC data.

The AAC frames appear to have invalid element tags, suggesting possible
encryption or obfuscation of the bitstream.
"""

import sys
from pathlib import Path


ELEMENT_NAMES = ['SCE', 'CPE', 'CCE', 'LFE', 'DSE', 'PCE', 'FIL', 'END']


def analyze_xor_patterns(adts_path):
    """Check for XOR encryption patterns in the AAC data."""

    with open(adts_path, "rb") as f:
        data = f.read()

    print(f"File: {adts_path}")
    print(f"Size: {len(data)} bytes")
    print("=" * 60)

    # Find frame offsets
    frames = []
    pos = 0
    while pos < len(data) - 7 and len(frames) < 50:
        if data[pos] == 0xFF and (data[pos+1] & 0xF0) == 0xF0:
            header = data[pos:pos+7]
            frame_len = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)
            protection_absent = header[1] & 1
            header_size = 7 if protection_absent else 9

            if frame_len >= header_size and pos + frame_len <= len(data):
                raw_start = pos + header_size
                raw_data = data[raw_start:raw_start+50]
                frames.append({
                    'index': len(frames),
                    'offset': pos,
                    'length': frame_len,
                    'raw_offset': raw_start,
                    'raw_data': raw_data
                })
                pos += frame_len
            else:
                pos += 1
        else:
            pos += 1

    print(f"Analyzed first {len(frames)} frames\n")

    # Frame 0 has valid PCE - analyze it
    print("Frame 0 (reference - has valid PCE):")
    frame0 = frames[0]
    print(f"  Offset: {frame0['offset']}")
    print(f"  Raw data: {frame0['raw_data'][:20].hex()}")
    first_byte = frame0['raw_data'][0]
    elem_id = (first_byte >> 5) & 7
    print(f"  First byte: 0x{first_byte:02x} -> elem={elem_id} ({ELEMENT_NAMES[elem_id]})")

    # Frame 1 has CPE tag=12 which is wrong
    print("\nFrame 1 (first problematic frame):")
    frame1 = frames[1]
    print(f"  Offset: {frame1['offset']}")
    print(f"  Raw data: {frame1['raw_data'][:20].hex()}")
    first_byte = frame1['raw_data'][0]
    elem_id = (first_byte >> 5) & 7
    instance = (first_byte >> 1) & 0xF
    print(f"  First byte: 0x{first_byte:02x} -> elem={elem_id} ({ELEMENT_NAMES[elem_id]}), tag={instance}")

    # In valid 8-channel AAC, frame 1 should start with defined channel elements
    # The PCE defines: CPE tag=0, SCE tag=0, CPE tag=1, CPE tag=2, SCE tag=1
    print("\n" + "=" * 60)
    print("XOR Pattern Analysis")
    print("=" * 60)

    print("\nTrying XOR patterns on first byte of frame 1 raw data:")
    first_byte = frame1['raw_data'][0]
    for xor_val in [0x00, 0x0C, 0x30, 0xC0, 0xCC, 0x60, 0x90, 0x18, 0x20, 0x28]:
        result = first_byte ^ xor_val
        elem_id = (result >> 5) & 7
        instance = (result >> 1) & 0xF
        marker = " <-- CPE tag=0!" if elem_id == 1 and instance == 0 else ""
        print(f"  XOR 0x{xor_val:02x}: 0x{result:02x} -> elem={elem_id}({ELEMENT_NAMES[elem_id]}), tag={instance}{marker}")

    # Check if there's a repeating XOR key
    print("\n" + "=" * 60)
    print("Checking for repeating XOR key patterns")
    print("=" * 60)

    # If frame 1 should start with CPE tag=0 (element_id=1, instance=0)
    # That would be: 001 0000 x = 0x20 or 0x21
    # Frame 1 first byte is 0x39
    # 0x39 XOR 0x?? = 0x20 -> ?? = 0x39 XOR 0x20 = 0x19

    expected_first_byte = 0x20  # CPE tag=0
    actual_first_byte = frame1['raw_data'][0]
    xor_key_byte1 = expected_first_byte ^ actual_first_byte
    print("\nIf frame 1 should start with CPE tag=0 (0x20):")
    print(f"  Actual: 0x{actual_first_byte:02x}")
    print(f"  Expected: 0x{expected_first_byte:02x}")
    print(f"  XOR key byte: 0x{xor_key_byte1:02x}")

    # Apply this key to a few frames and see if it makes sense
    print(f"\nApplying XOR 0x{xor_key_byte1:02x} to first bytes of frames 1-10:")
    for frame in frames[1:11]:
        first_byte = frame['raw_data'][0]
        result = first_byte ^ xor_key_byte1
        elem_id = (result >> 5) & 7
        instance = (result >> 1) & 0xF
        print(f"  Frame {frame['index']}: 0x{first_byte:02x} -> 0x{result:02x} = {ELEMENT_NAMES[elem_id]} tag={instance}")

    # Check frame sizes for patterns
    print("\n" + "=" * 60)
    print("Frame size analysis")
    print("=" * 60)
    print("\nFrame sizes (first 20):")
    for frame in frames[:20]:
        print(f"  Frame {frame['index']}: {frame['length']} bytes at offset {frame['offset']}")

    # Look for any obvious patterns in raw data
    print("\n" + "=" * 60)
    print("Raw data patterns")
    print("=" * 60)
    print("\nFirst 10 bytes of each frame's raw data:")
    for frame in frames[:15]:
        print(f"  Frame {frame['index']:2d}: {frame['raw_data'][:10].hex()}")

    # Check if UUID might be the key
    print("\n" + "=" * 60)
    print("UUID-based key check")
    print("=" * 60)
    print("\nFile UUID from typical filename: 0f7da717-a4c6-46be-994e-eca19516836c")
    uuid_bytes = bytes.fromhex("0f7da717a4c646be994eeca19516836c")
    print(f"UUID as bytes: {uuid_bytes.hex()}")

    print("\nApplying UUID XOR to frame 1 raw data (first 16 bytes):")
    frame1_raw = frame1['raw_data'][:16]
    result = bytes(a ^ b for a, b in zip(frame1_raw, uuid_bytes))
    print(f"  Original: {frame1_raw.hex()}")
    print(f"  UUID key: {uuid_bytes.hex()}")
    print(f"  XOR'd:    {result.hex()}")

    # Check first element after XOR
    first_byte = result[0]
    elem_id = (first_byte >> 5) & 7
    instance = (first_byte >> 1) & 0xF
    print(f"  First element after XOR: {ELEMENT_NAMES[elem_id]} tag={instance}")


def check_frame_dependent_key(frames):
    """Check if the XOR key depends on frame number or offset."""
    print("\n" + "=" * 60)
    print("Frame-dependent key analysis")
    print("=" * 60)

    # The expected sequence for 8-channel AAC with PCE configuration:
    # CPE tag=0, SCE tag=0, CPE tag=1, CPE tag=2, SCE tag=1, END
    # In binary: 001 0000 x, 000 0000 x, 001 0001 x, 001 0010 x, 000 0001 x, 111 xxxx x
    _expected_elements = [
        (1, 0),   # CPE tag=0
        (0, 0),   # SCE tag=0
        (1, 1),   # CPE tag=1
        (1, 2),   # CPE tag=2
        (0, 1),   # SCE tag=1
    ]

    print("\nChecking if XOR key = frame_index:")
    for i, frame in enumerate(frames[1:11], 1):
        first_byte = frame['raw_data'][0]
        result = first_byte ^ i
        elem_id = (result >> 5) & 7
        instance = (result >> 1) & 0xF
        print(f"  Frame {i}: 0x{first_byte:02x} XOR {i} = 0x{result:02x} -> {ELEMENT_NAMES[elem_id]} tag={instance}")

    print("\nChecking if XOR key = frame_offset & 0xFF:")
    for frame in frames[1:11]:
        first_byte = frame['raw_data'][0]
        key = frame['offset'] & 0xFF
        result = first_byte ^ key
        elem_id = (result >> 5) & 7
        instance = (result >> 1) & 0xF
        print(f"  Frame {frame['index']}: 0x{first_byte:02x} XOR 0x{key:02x} = 0x{result:02x} -> {ELEMENT_NAMES[elem_id]} tag={instance}")

    print("\nChecking if XOR key = frame_length & 0xFF:")
    for frame in frames[1:11]:
        first_byte = frame['raw_data'][0]
        key = frame['length'] & 0xFF
        result = first_byte ^ key
        elem_id = (result >> 5) & 7
        instance = (result >> 1) & 0xF
        print(f"  Frame {frame['index']}: 0x{first_byte:02x} XOR 0x{key:02x} = 0x{result:02x} -> {ELEMENT_NAMES[elem_id]} tag={instance}")

    # Check if each frame has its own consistent transformation
    print("\nRequired XOR values to get expected CPE tag=0 (0x20 or 0x21):")
    for frame in frames[1:20]:
        first_byte = frame['raw_data'][0]
        xor_for_20 = first_byte ^ 0x20
        xor_for_21 = first_byte ^ 0x21
        print(f"  Frame {frame['index']:2d}: 0x{first_byte:02x} needs XOR 0x{xor_for_20:02x} or 0x{xor_for_21:02x}")


def main():
    """Analyze XOR patterns for a given ADTS/AAC file."""
    if len(sys.argv) < 2:
        if Path("brute_force_output/raw.aac").exists():
            adts_path = "brute_force_output/raw.aac"
        else:
            print("Usage: python check_xor_encryption.py <file.aac>")
            sys.exit(1)
    else:
        adts_path = sys.argv[1]

    # Parse frames first
    with open(adts_path, "rb") as f:
        data = f.read()

    frames = []
    pos = 0
    while pos < len(data) - 7 and len(frames) < 50:
        if data[pos] == 0xFF and (data[pos+1] & 0xF0) == 0xF0:
            header = data[pos:pos+7]
            frame_len = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)
            protection_absent = header[1] & 1
            header_size = 7 if protection_absent else 9

            if frame_len >= header_size and pos + frame_len <= len(data):
                raw_start = pos + header_size
                raw_data = data[raw_start:raw_start+50]
                frames.append({
                    'index': len(frames),
                    'offset': pos,
                    'length': frame_len,
                    'raw_offset': raw_start,
                    'raw_data': raw_data
                })
                pos += frame_len
            else:
                pos += 1
        else:
            pos += 1

    analyze_xor_patterns(adts_path)
    check_frame_dependent_key(frames)


if __name__ == '__main__':
    main()
