#!/usr/bin/env python3
"""
Aggressive MP4 patching to extract stems from Engine DJ files.

Strategy: Rewrite the MP4 container with a modified AudioSpecificConfig
that uses channelConfiguration=7 (standard 8-channel) instead of PCE.
"""

import struct
import sys
import subprocess
from pathlib import Path


def read_uint32_be(data, offset):
    return struct.unpack('>I', data[offset:offset+4])[0]


def write_uint32_be(value):
    return struct.pack('>I', value)


def read_uint64_be(data, offset):
    return struct.unpack('>Q', data[offset:offset+8])[0]


def find_atom(data, atom_type, start=0, end=None):
    """Find an atom by type and return (offset, size)."""
    if end is None:
        end = len(data)

    pos = start
    while pos < end:
        if pos + 8 > end:
            break

        size = read_uint32_be(data, pos)
        atype = data[pos+4:pos+8]

        if size == 0:
            # Atom extends to end of file
            size = end - pos
        elif size == 1:
            # 64-bit size
            if pos + 16 > end:
                break
            size = read_uint64_be(data, pos + 8)

        if atype == atom_type:
            return pos, size

        if size < 8:
            break
        pos += size

    return None, None


def find_atom_path(data, path):
    """Find nested atom by path like [b'moov', b'trak', b'mdia']."""
    pos = 0
    size = len(data)

    for atom_type in path:
        found_pos, found_size = find_atom(data, atom_type, pos, pos + size)
        if found_pos is None:
            return None, None

        # Move inside the atom (skip header)
        header_size = 8
        if read_uint32_be(data, found_pos) == 1:
            header_size = 16

        pos = found_pos + header_size
        size = found_size - header_size

    # Return the full atom (including header)
    return found_pos, found_size


def find_esds(data):
    """Find the esds atom containing AudioSpecificConfig."""
    # Navigate: moov -> trak -> mdia -> minf -> stbl -> stsd -> mp4a -> esds
    path_to_stsd = [b'moov', b'trak', b'mdia', b'minf', b'stbl', b'stsd']

    stsd_pos, stsd_size = find_atom_path(data, path_to_stsd)
    if stsd_pos is None:
        print("Could not find stsd atom")
        return None, None

    # stsd has a 8-byte header (version/flags + entry count)
    stsd_data_start = stsd_pos + 8 + 8  # atom header + stsd header

    # Find mp4a within stsd
    mp4a_pos, mp4a_size = find_atom(data, b'mp4a', stsd_data_start, stsd_pos + stsd_size)
    if mp4a_pos is None:
        print("Could not find mp4a atom")
        return None, None

    # mp4a has 28 bytes of audio sample entry before child atoms
    mp4a_children_start = mp4a_pos + 8 + 28

    # Find esds within mp4a
    esds_pos, esds_size = find_atom(data, b'esds', mp4a_children_start, mp4a_pos + mp4a_size)
    if esds_pos is None:
        print("Could not find esds atom")
        return None, None

    return esds_pos, esds_size


def parse_esds_and_find_asc(data, esds_pos, esds_size):
    """Parse ESDS and find the AudioSpecificConfig location and content."""
    # esds atom: 8-byte header + 4-byte version/flags
    esds_data = data[esds_pos + 8 + 4 : esds_pos + esds_size]

    offset = 0

    def read_descriptor():
        nonlocal offset
        tag = esds_data[offset]
        offset += 1

        # Read size (1-4 bytes with continuation bit)
        size = 0
        for _ in range(4):
            b = esds_data[offset]
            offset += 1
            size = (size << 7) | (b & 0x7F)
            if b & 0x80 == 0:
                break

        return tag, size

    # ES_Descriptor (tag 0x03)
    tag, size = read_descriptor()
    if tag != 0x03:
        print(f"Expected ES_Descriptor (0x03), got 0x{tag:02x}")
        return None, None

    # ES_ID (2 bytes)
    offset += 2
    # flags (1 byte)
    flags = esds_data[offset]
    offset += 1

    if flags & 0x80:  # streamDependenceFlag
        offset += 2
    if flags & 0x40:  # URL_Flag
        url_len = esds_data[offset]
        offset += 1 + url_len
    if flags & 0x20:  # OCRstreamFlag
        offset += 2

    # DecoderConfigDescriptor (tag 0x04)
    tag, size = read_descriptor()
    if tag != 0x04:
        print(f"Expected DecoderConfigDescriptor (0x04), got 0x{tag:02x}")
        return None, None

    # objectTypeIndication (1 byte) = 0x40 for AAC
    # streamType (1 byte)
    # bufferSizeDB (3 bytes)
    # maxBitrate (4 bytes)
    # avgBitrate (4 bytes)
    offset += 1 + 1 + 3 + 4 + 4

    # DecoderSpecificInfo (tag 0x05) = AudioSpecificConfig
    # dsi_start_offset = offset
    tag, size = read_descriptor()
    if tag != 0x05:
        print(f"Expected DecoderSpecificInfo (0x05), got 0x{tag:02x}")
        return None, None

    # The ASC data
    asc_offset_in_esds = offset
    asc_data = esds_data[offset:offset + size]

    # Calculate absolute offset in file
    # esds_pos + 8 (atom header) + 4 (version) + asc_offset
    asc_absolute_offset = esds_pos + 8 + 4 + asc_offset_in_esds

    return asc_absolute_offset, asc_data


def create_new_asc_8ch():
    """Create a new AudioSpecificConfig for 8-channel standard configuration.

    Unfortunately there's no standard channelConfiguration for 8 arbitrary channels.
    channelConfiguration values:
    0 = defined in PCE
    1 = 1 channel (mono)
    2 = 2 channels (stereo)
    3 = 3 channels (C, L, R)
    4 = 4 channels (C, L, R, rear)
    5 = 5 channels (C, L, R, SL, SR)
    6 = 6 channels (5.1)
    7 = 8 channels (7.1: C, L, R, SL, SR, BL, BR, LFE)

    Let's try 7 (7.1) and see if decoders handle the stem layout.
    """
    # audioObjectType = 2 (AAC-LC), 5 bits
    # samplingFrequencyIndex = 4 (44100 Hz), 4 bits
    # channelConfiguration = 7 (8 channels), 4 bits
    # remaining bits = 0

    # Bits: 00010 0100 0111 000
    #       -----|----|----
    #       aot=2 sri=4 ch=7

    # 00010010 00111000 = 0x12 0x38
    return bytes([0x12, 0x38])


def create_new_asc_stereo():
    """Create AudioSpecificConfig for stereo (for splitting approach)."""
    # audioObjectType = 2 (AAC-LC), 5 bits
    # samplingFrequencyIndex = 4 (44100 Hz), 4 bits
    # channelConfiguration = 2 (stereo), 4 bits

    # Bits: 00010 0100 0010 000
    # 00010010 00010000 = 0x12 0x10
    return bytes([0x12, 0x10])


def patch_mp4_8channel(input_path, output_path):
    """Create patched MP4 with standard 8-channel configuration."""
    print(f"Reading {input_path}...")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    print("Finding esds atom...")
    esds_pos, esds_size = find_esds(data)
    if esds_pos is None:
        print("Failed to find esds atom")
        return False

    print(f"Found esds at offset {esds_pos}, size {esds_size}")

    print("Finding AudioSpecificConfig...")
    asc_offset, asc_data = parse_esds_and_find_asc(data, esds_pos, esds_size)
    if asc_offset is None:
        print("Failed to find AudioSpecificConfig")
        return False

    print(f"Found ASC at offset {asc_offset}, size {len(asc_data)}")
    print(f"Original ASC: {asc_data.hex()}")

    # The original ASC has PCE - it's much larger than a simple config
    # We need to replace it with a minimal 2-byte config
    # But the size field in the ESDS is encoded, so this is tricky

    # Simpler approach: just patch the first 2 bytes to change the config
    # Original first 2 bytes: 0x12 0x00 (aot=2, sri=4, ch=0)
    # New first 2 bytes: 0x12 0x38 (aot=2, sri=4, ch=7)

    new_asc_start = create_new_asc_8ch()
    print(f"New ASC start: {new_asc_start.hex()}")

    # Patch just the channel configuration nibble
    # Byte 1 (index 1) bits 7-4 contain the channel config
    # Original: 0x00 (ch=0, then PCE follows)
    # We want: 0x38 (ch=7, then stop)

    data[asc_offset] = 0x12  # Keep aot=2, sri=4
    data[asc_offset + 1] = 0x38  # ch=7

    print(f"Writing patched file to {output_path}...")
    with open(output_path, 'wb') as f:
        f.write(data)

    print("Done!")
    return True


def patch_mp4_as_stereo(input_path, output_path):
    """Create patched MP4 claiming to be stereo (may help some decoders)."""
    print(f"Reading {input_path}...")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    print("Finding esds atom...")
    esds_pos, esds_size = find_esds(data)
    if esds_pos is None:
        print("Failed to find esds atom")
        return False

    print("Finding AudioSpecificConfig...")
    asc_offset, asc_data = parse_esds_and_find_asc(data, esds_pos, esds_size)
    if asc_offset is None:
        print("Failed to find AudioSpecificConfig")
        return False

    print(f"Original ASC: {asc_data.hex()}")

    # Patch to stereo
    data[asc_offset] = 0x12
    data[asc_offset + 1] = 0x10  # ch=2 (stereo)

    print(f"Writing stereo-patched file to {output_path}...")
    with open(output_path, 'wb') as f:
        f.write(data)

    return True


# def rebuild_esds_with_new_asc(data, esds_pos, esds_size, new_asc):
#     """Rebuild the esds atom with a completely new ASC.

#     This is complex because we need to:
#     1. Parse the existing esds structure
#     2. Replace the ASC while updating all size fields
#     3. Update parent atom sizes if the esds size changed
#     """
#     # For now, let's use a simpler approach - patch in place
#     # The decoder should stop reading ASC after it gets a valid config
#     pass


def main():
    """CLI to patch MP4 ASC for 8ch or stereo and probe/decode outputs."""
    if len(sys.argv) < 2:
        stems_dir = Path("stems")
        if stems_dir.exists():
            stems = list(stems_dir.glob("*.stems"))
            if stems:
                input_file = str(stems[0])
            else:
                print("Usage: python patch_mp4.py <input.stems> [output.mp4]")
                sys.exit(1)
        else:
            print("Usage: python patch_mp4.py <input.stems> [output.mp4]")
            sys.exit(1)
    else:
        input_file = sys.argv[1]

    base_name = Path(input_file).stem
    output_dir = Path("patched")
    output_dir.mkdir(exist_ok=True)

    # Create 8-channel patched version
    output_8ch = output_dir / f"{base_name}_8ch.mp4"
    print("\n=== Creating 8-channel patched version ===")
    patch_mp4_8channel(input_file, str(output_8ch))

    # Create stereo patched version
    output_stereo = output_dir / f"{base_name}_stereo.mp4"
    print("\n=== Creating stereo patched version ===")
    patch_mp4_as_stereo(input_file, str(output_stereo))

    print("\n=== Testing with ffprobe ===")

    print("\nOriginal file:")
    subprocess.run(['ffprobe', '-v', 'error', '-show_entries',
                   'stream=codec_name,channels,sample_rate', '-of', 'default',
                   input_file], check=False)

    print("\n8-channel patched:")
    subprocess.run(['ffprobe', '-v', 'error', '-show_entries',
                   'stream=codec_name,channels,sample_rate', '-of', 'default',
                   str(output_8ch)], check=False)

    print("\nStereo patched:")
    subprocess.run(['ffprobe', '-v', 'error', '-show_entries',
                   'stream=codec_name,channels,sample_rate', '-of', 'default',
                   str(output_stereo)], check=False)

    print("\n=== Attempting decode of 8-channel patched ===")
    output_wav = output_dir / f"{base_name}_8ch.wav"
    result = subprocess.run([
        'ffmpeg', '-y', '-v', 'error',
        '-i', str(output_8ch),
        '-c:a', 'pcm_s16le',
        str(output_wav)
    ], capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print(f"SUCCESS! Decoded to {output_wav}")
        print("Now splitting into stems...")

        # Split 8 channels into 4 stereo stems
        stem_names = ['drums', 'bass', 'melody', 'vocals']
        for i, name in enumerate(stem_names):
            stem_file = output_dir / f"{base_name}_{name}.wav"
            left_ch = i * 2
            right_ch = i * 2 + 1

            subprocess.run([
                'ffmpeg', '-y', '-v', 'error',
                '-i', str(output_wav),
                '-filter_complex', f'[0:a]pan=stereo|c0=c{left_ch}|c1=c{right_ch}[out]',
                '-map', '[out]',
                str(stem_file)
            ], check=False)
            print(f"  Created {stem_file}")
    else:
        print(f"Decode failed: {result.stderr}")

        print("\n=== Attempting decode of stereo patched (will lose channels) ===")
        output_stereo_wav = output_dir / f"{base_name}_stereo.wav"
        result = subprocess.run([
            'ffmpeg', '-y', '-v', 'warning',
            '-i', str(output_stereo),
            '-c:a', 'pcm_s16le',
            str(output_stereo_wav)
        ], capture_output=True, text=True, check=False)

        if result.returncode == 0:
            print(f"Stereo decode succeeded: {output_stereo_wav}")
            print("(Note: This only captured 2 channels, not all 8)")
        else:
            print(f"Stereo decode also failed: {result.stderr}")


if __name__ == '__main__':
    main()
