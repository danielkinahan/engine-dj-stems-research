#!/usr/bin/env python3
"""
Detailed ADTS frame analysis for Engine DJ stems files.
"""

import sys
import subprocess
from pathlib import Path

SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000]
ELEMENT_NAMES = ['SCE', 'CPE', 'CCE', 'LFE', 'DSE', 'PCE', 'FIL', 'END']


def analyze_adts_frames(adts_path, max_frames=10):
    """Analyze ADTS frames in detail.

    Reads the ADTS stream, iterates frames, and prints header and
    first raw data element information for quick inspection.
    """
    with open(adts_path, "rb") as f:
        data = f.read()

    print(f"File: {adts_path}")
    print(f"Total size: {len(data)} bytes")
    print("=" * 60)

    pos = 0
    frame_num = 0

    while pos < len(data) - 7 and frame_num < max_frames:
        # Sync word check
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue

        header = data[pos:pos+7]

        # Parse ADTS header
        mpeg_version = (header[1] >> 3) & 1  # 0=MPEG-4, 1=MPEG-2
        protection_absent = header[1] & 1
        profile = (header[2] >> 6) & 3  # 0=Main, 1=LC, 2=SSR, 3=reserved
        sampling_freq_idx = (header[2] >> 2) & 0xF
        channel_config = ((header[2] & 1) << 2) | ((header[3] >> 6) & 3)

        frame_length = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)
        buffer_fullness = ((header[5] & 0x1F) << 6) | ((header[6] >> 2) & 0x3F)
        num_raw_blocks = header[6] & 3

        header_size = 7 if protection_absent else 9

        sample_rate = SAMPLE_RATES[sampling_freq_idx] if sampling_freq_idx < len(SAMPLE_RATES) else 'reserved'

        print(f"\nFrame {frame_num} at offset {pos} (0x{pos:x}):")
        print(f"  Header (hex): {header.hex()}")
        print(f"  MPEG version: {'MPEG-2' if mpeg_version else 'MPEG-4'}")
        print(f"  Profile: {['Main', 'LC', 'SSR', 'reserved'][profile]} ({profile})")
        print(f"  Sample rate idx: {sampling_freq_idx} ({sample_rate} Hz)")
        print(f"  Channel config: {channel_config}")
        print(f"  Frame length: {frame_length} bytes")
        print(f"  Buffer fullness: {buffer_fullness}")
        print(f"  Raw blocks: {num_raw_blocks + 1}")
        print(f"  Protection absent: {protection_absent}")

        # Look at raw data block start
        raw_start = pos + header_size
        raw_data = data[raw_start:raw_start+30]
        print(f"  Raw data start (hex): {raw_data[:20].hex()}")

        # Parse first syntactic elements
        if channel_config == 0:
            print("  [Channel config 0 = PCE defined in bitstream]")
            parse_raw_data_block(raw_data)

        pos += frame_length
        frame_num += 1

    # Count total frames
    pos = 0
    total_frames = 0
    while pos < len(data) - 7:
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue
        header = data[pos:pos+7]
        frame_length = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)
        if frame_length < 7:
            pos += 1
            continue
        total_frames += 1
        pos += frame_length

    print(f"\n{'=' * 60}")
    print(f"Total frames: {total_frames}")
    print(f"Expected duration: {total_frames * 1024 / 44100:.1f} seconds")


def parse_raw_data_block(raw_data):
    """Parse the raw data block to identify syntactic elements."""
    if len(raw_data) < 1:
        return

    # Create bit reader
    class BitReader:
        """Minimal bit reader for parsing AAC raw blocks."""

        def __init__(self, data):
            """Initialize with bytes-like `data`."""
            self.data = data
            self.byte_pos = 0
            self.bit_pos = 0

        def read_bits(self, n):
            """Read `n` bits and return as integer, or None at EOF."""
            result = 0
            for _ in range(n):
                if self.byte_pos >= len(self.data):
                    return None
                bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1
                result = (result << 1) | bit
                self.bit_pos += 1
                if self.bit_pos >= 8:
                    self.bit_pos = 0
                    self.byte_pos += 1
            return result

        def position(self):
            """Return current bit position (absolute)."""
            return self.byte_pos * 8 + self.bit_pos

    br = BitReader(raw_data)

    # Read first element
    elem_id = br.read_bits(3)
    if elem_id is None:
        return

    elem_name = ELEMENT_NAMES[elem_id] if elem_id < len(ELEMENT_NAMES) else 'unknown'
    print(f"  First element ID: {elem_id} ({elem_name})")

    if elem_id == 5:  # PCE
        parse_pce(br)
    elif elem_id == 0:  # SCE (Single Channel Element)
        instance_tag = br.read_bits(4)
        print(f"    SCE instance tag: {instance_tag}")
    elif elem_id == 1:  # CPE (Channel Pair Element)
        instance_tag = br.read_bits(4)
        print(f"    CPE instance tag: {instance_tag}")


def parse_pce(br):
    """Parse Program Config Element."""
    element_instance_tag = br.read_bits(4)
    object_type = br.read_bits(2)
    sampling_frequency_index = br.read_bits(4)
    num_front_channel_elements = br.read_bits(4)
    num_side_channel_elements = br.read_bits(4)
    num_back_channel_elements = br.read_bits(4)
    num_lfe_channel_elements = br.read_bits(2)
    num_assoc_data_elements = br.read_bits(3)
    num_valid_cc_elements = br.read_bits(4)

    print("    PCE:")
    print(f"      element_instance_tag: {element_instance_tag}")
    print(f"      object_type: {object_type} ({['Main', 'LC', 'SSR', 'LTP'][object_type]})")
    sr_text = (f"{SAMPLE_RATES[sampling_frequency_index]} Hz"
               if sampling_frequency_index < len(SAMPLE_RATES) else 'reserved')
    print(f"      sampling_frequency_index: {sampling_frequency_index} ({sr_text})")
    print(f"      num_front_channel_elements: {num_front_channel_elements}")
    print(f"      num_side_channel_elements: {num_side_channel_elements}")
    print(f"      num_back_channel_elements: {num_back_channel_elements}")
    print(f"      num_lfe_channel_elements: {num_lfe_channel_elements}")
    print(f"      num_assoc_data_elements: {num_assoc_data_elements}")
    print(f"      num_valid_cc_elements: {num_valid_cc_elements}")

    # mono_mixdown_present
    mono_mixdown_present = br.read_bits(1)
    if mono_mixdown_present:
        br.read_bits(4)  # mono_mixdown_element_number

    # stereo_mixdown_present
    stereo_mixdown_present = br.read_bits(1)
    if stereo_mixdown_present:
        br.read_bits(4)  # stereo_mixdown_element_number

    # matrix_mixdown_idx_present
    matrix_mixdown_idx_present = br.read_bits(1)
    if matrix_mixdown_idx_present:
        br.read_bits(2)  # matrix_mixdown_idx
        br.read_bits(1)  # pseudo_surround_enable

    total_channels = 0

    # Front channel elements
    for i in range(num_front_channel_elements):
        is_cpe = br.read_bits(1)
        element_tag = br.read_bits(4)
        channels = 2 if is_cpe else 1
        total_channels += channels
        print(f"      front[{i}]: {'CPE' if is_cpe else 'SCE'} tag={element_tag} ({channels}ch)")

    # Side channel elements
    for i in range(num_side_channel_elements):
        is_cpe = br.read_bits(1)
        element_tag = br.read_bits(4)
        channels = 2 if is_cpe else 1
        total_channels += channels
        print(f"      side[{i}]: {'CPE' if is_cpe else 'SCE'} tag={element_tag} ({channels}ch)")

    # Back channel elements
    for i in range(num_back_channel_elements):
        is_cpe = br.read_bits(1)
        element_tag = br.read_bits(4)
        channels = 2 if is_cpe else 1
        total_channels += channels
        print(f"      back[{i}]: {'CPE' if is_cpe else 'SCE'} tag={element_tag} ({channels}ch)")

    # LFE channel elements
    for i in range(num_lfe_channel_elements):
        element_tag = br.read_bits(4)
        total_channels += 1
        print(f"      lfe[{i}]: SCE tag={element_tag} (1ch)")

    print(f"      Total channels: {total_channels}")


def main():
    """Entry point: analyze a provided ADTS stream or extract from stems."""
    if len(sys.argv) < 2:
        # Try to find raw.aac or extract from stems
        if Path("brute_force_output/raw.aac").exists():
            adts_path = "brute_force_output/raw.aac"
        else:
            stems_dir = Path("stems")
            if stems_dir.exists():
                stems = list(stems_dir.glob("*.stems"))
                if stems:
                    adts_path = "temp_analysis.aac"
                    subprocess.run([
                        'ffmpeg', '-y', '-v', 'error',
                        '-i', str(stems[0]),
                        '-c:a', 'copy', '-f', 'adts',
                        adts_path
                    ], check=False)
                else:
                    print("Usage: python analyze_adts_detail.py <file.aac>")
                    sys.exit(1)
            else:
                print("Usage: python analyze_adts_detail.py <file.aac>")
                sys.exit(1)
    else:
        adts_path = sys.argv[1]

    max_frames = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    analyze_adts_frames(adts_path, max_frames)


if __name__ == '__main__':
    main()
