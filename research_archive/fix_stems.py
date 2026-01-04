#!/usr/bin/env python3
"""
Fix Engine DJ .stems files by modifying the AudioSpecificConfig to use
standard channel configuration instead of PCE.

The problem: Engine DJ creates AAC with channelConfiguration=0 (meaning PCE is used),
but the PCE is only in the AudioSpecificConfig, not in each frame. Many decoders
don't handle this correctly.

Solution: Modify the esds atom to use channelConfiguration=7 (7.1 = 8 channels)
which is the closest standard configuration, then decode.
"""

import struct
import sys
import os
import subprocess
import tempfile
from pathlib import Path


def find_atom(data: bytes, path: list, offset: int = 0, size: int = None) -> tuple:
    """Find an atom in MP4 data by path. Returns (offset, size) or None."""
    if size is None:
        size = len(data)

    end = offset + size
    pos = offset

    while pos < end - 8:
        atom_size = struct.unpack('>I', data[pos:pos+4])[0]
        atom_type = data[pos+4:pos+8]

        if atom_size == 0:  # extends to end of file
            atom_size = end - pos
        elif atom_size == 1:  # 64-bit size
            atom_size = struct.unpack('>Q', data[pos+8:pos+16])[0]

        if atom_size < 8:
            break

        if atom_type == path[0]:
            if len(path) == 1:
                return (pos, atom_size)
            # Container atom - recurse
            header_size = 8 if atom_size != 1 else 16
            # stsd has a version/flags and entry count
            if atom_type == b'stsd':
                header_size += 8  # version/flags(4) + entry_count(4)
            # mp4a has extra fields
            elif atom_type == b'mp4a':
                header_size += 28  # standard audio sample entry fields
            return find_atom(data, path[1:], pos + header_size, atom_size - header_size)

        pos += atom_size

    return None


def parse_asc(asc: bytes) -> dict:
    """Parse AudioSpecificConfig."""
    if len(asc) < 2:
        return None

    bits = int.from_bytes(asc, 'big')
    total_bits = len(asc) * 8

    def get_bits(start, length):
        shift = total_bits - start - length
        mask = (1 << length) - 1
        return (bits >> shift) & mask

    audio_object_type = get_bits(0, 5)
    sample_rate_index = get_bits(5, 4)
    channel_config = get_bits(9, 4)

    return {
        'object_type': audio_object_type,
        'sample_rate_index': sample_rate_index,
        'channel_config': channel_config,
        'raw': asc.hex()
    }


def fix_asc_channel_config(asc: bytes, new_channel_config: int = 7) -> bytes:
    """
    Modify AudioSpecificConfig to use a standard channel configuration.

    Original ASC format:
    - 5 bits: audioObjectType
    - 4 bits: samplingFrequencyIndex
    - 4 bits: channelConfiguration (0 = PCE follows)
    - ... rest including PCE if channelConfig=0

    We want to change channelConfiguration from 0 to 7 (7.1 surround = 8 channels)
    and remove the PCE data.
    """
    if len(asc) < 2:
        return asc

    # Parse first 13 bits (5 + 4 + 4)
    val = int.from_bytes(asc[:2], 'big')

    audio_object_type = (val >> 11) & 0x1F
    sample_rate_index = (val >> 7) & 0x0F
    old_channel_config = (val >> 3) & 0x0F

    print(f"  Original ASC: {asc.hex()}")
    print(f"    Object type: {audio_object_type}")
    print(f"    Sample rate index: {sample_rate_index}")
    print(f"    Channel config: {old_channel_config}")

    if old_channel_config != 0:
        print(f"  Channel config is already {old_channel_config}, not modifying")
        return asc

    # Create new ASC with standard channel config
    # For 8 channels, channelConfiguration=7 (7.1) is closest standard
    new_val = (audio_object_type << 11) | (sample_rate_index << 7) | (new_channel_config << 3)
    # Add frameLengthFlag=0, dependsOnCoreCoder=0, extensionFlag=0

    new_asc = new_val.to_bytes(2, 'big')
    print(f"  New ASC: {new_asc.hex()}")
    print(f"    Channel config: {new_channel_config}")

    return new_asc


def fix_stems_file(input_path: str, output_path: str) -> bool:
    """Fix a .stems file by modifying the AudioSpecificConfig."""

    print(f"Reading: {input_path}")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    print(f"File size: {len(data):,} bytes")

    # Find moov atom
    moov_info = find_atom(data, [b'moov'])
    if not moov_info:
        print("Could not find moov atom")
        return False
    print(f"Found moov at offset {moov_info[0]}")

    # Find esds inside moov/trak/mdia/minf/stbl/stsd/mp4a/esds
    # Actually, let's search more broadly for esds

    # Find all esds atoms by scanning
    esds_locations = []
    pos = 0
    while pos < len(data) - 8:
        if data[pos+4:pos+8] == b'esds':
            size = struct.unpack('>I', data[pos:pos+4])[0]
            esds_locations.append((pos, size))
            print(f"Found esds at offset {pos}, size {size}")
        pos += 1

    if not esds_locations:
        print("Could not find esds atom")
        return False

    modified = False
    for esds_offset, esds_size in esds_locations:
        print(f"\nProcessing esds at {esds_offset}")

        # esds structure:
        # 4 bytes: size
        # 4 bytes: 'esds'
        # 4 bytes: version/flags
        # ES_Descriptor...

        esds_data = data[esds_offset:esds_offset + esds_size]

        # Skip header (8 bytes) and version/flags (4 bytes)
        es_desc_start = 12

        # ES_Descriptor has tag 0x03
        if esds_data[es_desc_start] != 0x03:
            print(f"  Expected ES_Descriptor tag 0x03, got {esds_data[es_desc_start]:02x}")
            continue

        # Parse descriptor length (can be 1-4 bytes with 0x80 continuation)
        pos = es_desc_start + 1
        es_len = 0
        for _ in range(4):
            b = esds_data[pos]
            es_len = (es_len << 7) | (b & 0x7F)
            pos += 1
            if b & 0x80 == 0:
                break

        # Skip ES_ID (2 bytes) and flags (1 byte)
        pos += 3

        # Now should be DecoderConfigDescriptor with tag 0x04
        if esds_data[pos] != 0x04:
            print(f"  Expected DecoderConfigDescriptor tag 0x04, got {esds_data[pos]:02x}")
            continue

        # Parse DecoderConfigDescriptor length
        pos += 1
        dec_len = 0
        for _ in range(4):
            b = esds_data[pos]
            dec_len = (dec_len << 7) | (b & 0x7F)
            pos += 1
            if b & 0x80 == 0:
                break

        # Skip objectTypeIndication(1), streamType/flags(1), bufferSizeDB(3), maxBitrate(4), avgBitrate(4)
        pos += 13

        # Now should be DecoderSpecificInfo with tag 0x05
        if esds_data[pos] != 0x05:
            print(f"  Expected DecoderSpecificInfo tag 0x05, got {esds_data[pos]:02x}")
            continue

        pos += 1
        asc_len = 0
        len_bytes = 0
        for _ in range(4):
            b = esds_data[pos]
            asc_len = (asc_len << 7) | (b & 0x7F)
            pos += 1
            len_bytes += 1
            if b & 0x80 == 0:
                break

        asc_offset = esds_offset + pos
        print(f"  ASC at offset {asc_offset}, length {asc_len}")

        old_asc = bytes(data[asc_offset:asc_offset + asc_len])
        new_asc = fix_asc_channel_config(old_asc)

        if new_asc != old_asc:
            # We need to replace the ASC and potentially adjust lengths
            # For now, just replace in place if same length
            if len(new_asc) == len(old_asc):
                data[asc_offset:asc_offset + len(old_asc)] = new_asc
                modified = True
            elif len(new_asc) < len(old_asc):
                # New ASC is shorter - we need to rebuild the esds atom
                # This is more complex, let's try a simpler approach:
                # Just modify the channel config bits in place without removing PCE
                print("  New ASC is shorter, modifying channel config in place...")

                # The channel config is at bits 9-12 of the ASC
                # We just need to set those 4 bits to 7 instead of 0
                # ASC byte 0: [AOT(5bits)][SRI(3bits)]
                # ASC byte 1: [SRI(1bit)][CC(4bits)][...rest]

                # Modify byte 1 to set channel config bits
                old_byte1 = data[asc_offset + 1]
                # Clear bits 3-6 (channel config) and set to 7
                new_byte1 = (old_byte1 & 0x87) | (7 << 3)
                data[asc_offset + 1] = new_byte1
                print(f"  Modified byte at {asc_offset + 1}: {old_byte1:02x} -> {new_byte1:02x}")
                modified = True
            else:
                print("  New ASC is longer, cannot modify in place")

    if modified:
        print(f"\nWriting: {output_path}")
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"File size: {len(data):,} bytes")
        return True
    else:
        print("\nNo modifications made")
        return False


def decode_fixed_file(fixed_path: str, output_dir: str) -> bool:
    """Decode the fixed file using ffmpeg."""

    stem_names = ['drums', 'bass', 'melody', 'vocals']

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # First decode to 8-channel WAV
    temp_wav = os.path.join(output_dir, '_full_8ch.wav')

    cmd = [
        'ffmpeg', '-y',
        '-i', fixed_path,
        '-c:a', 'pcm_s16le',
        '-ac', '8',
        temp_wav
    ]

    print("\nDecoding to 8-channel WAV...")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        print(f"Decode failed: {result.stderr[-500:]}")
        return False

    # Check output size
    if not os.path.exists(temp_wav) or os.path.getsize(temp_wav) < 1000000:
        print("Output too small or missing")
        return False

    print(f"  Created: {temp_wav} ({os.path.getsize(temp_wav) / 1024 / 1024:.2f} MB)")

    # Split into stems
    print("\nSplitting into stems...")
    for i, name in enumerate(stem_names):
        left = i * 2
        right = i * 2 + 1

        output_path = os.path.join(output_dir, f'{name}.wav')

        cmd = [
            'ffmpeg', '-y',
            '-i', temp_wav,
            '-af', f'pan=stereo|c0=c{left}|c1=c{right}',
            output_path
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode == 0 and os.path.exists(output_path):
            print(f"  ✓ {name}.wav ({os.path.getsize(output_path) / 1024 / 1024:.2f} MB)")
        else:
            print(f"  ✗ {name}: {result.stderr[-200:]}")

    # Clean up temp file
    os.remove(temp_wav)

    return True


def main():
    """CLI to patch ASC channel config and decode stems."""
    if len(sys.argv) < 2:
        print("Usage: python fix_stems.py <stems_file> [output_dir]")
        print("\nThis tool fixes Engine DJ .stems files that have AAC decoding issues")
        print("by modifying the channel configuration in the AudioSpecificConfig.")
        sys.exit(1)

    input_path = sys.argv[1]

    base_name = Path(input_path).stem
    output_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(input_path).parent / base_name)

    # Create fixed file in temp location
    with tempfile.NamedTemporaryFile(suffix='.m4a', delete=False) as tmp:
        fixed_path = tmp.name

    try:
        if fix_stems_file(input_path, fixed_path):
            decode_fixed_file(fixed_path, output_dir)
        else:
            print("Failed to fix file")
    finally:
        if os.path.exists(fixed_path):
            os.remove(fixed_path)


if __name__ == "__main__":
    main()
