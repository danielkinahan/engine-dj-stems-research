#!/usr/bin/env python3
"""
Engine DJ Stems Analyzer

Comprehensive analysis tool for Engine DJ .stems files.
Analyzes container format, audio configuration, PCE structure, and encryption patterns.

Usage:
    python analyze.py [stems_file.stems] [options]

Options:
    --frames N      Number of ADTS frames to analyze (default: 10)
    --xor           Include XOR encryption analysis
    --all           Run all analyses
"""

import struct
import sys
import subprocess
import tempfile
from pathlib import Path


# ============================================================================
# Constants
# ============================================================================

SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                16000, 12000, 11025, 8000, 7350]

ELEMENT_NAMES = ['SCE', 'CPE', 'CCE', 'LFE', 'DSE', 'PCE', 'FIL', 'END']

AOT_NAMES = {
    1: 'AAC Main', 2: 'AAC LC', 3: 'AAC SSR', 4: 'AAC LTP',
    5: 'SBR', 6: 'AAC Scalable', 29: 'PS'
}


# ============================================================================
# Bit Reader Helper
# ============================================================================

class BitReader:
    """Helper class for reading bits from a byte array."""

    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 0

    def read_bits(self, n):
        """Read n bits and return as integer."""
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
        """Return current bit position."""
        return self.byte_pos * 8 + self.bit_pos


# ============================================================================
# MP4 Container Parsing
# ============================================================================

def read_atom_header(f):
    """Read an MP4 atom header, returns (size, type, header_size)."""
    data = f.read(8)
    if len(data) < 8:
        return None, None, 0

    size = struct.unpack('>I', data[:4])[0]
    atom_type = data[4:8]
    header_size = 8

    if size == 1:  # 64-bit extended size
        ext_size = f.read(8)
        size = struct.unpack('>Q', ext_size)[0]
        header_size = 16
    elif size == 0:  # Extends to end of file
        pos = f.tell()
        f.seek(0, 2)
        size = f.tell() - pos + 8
        f.seek(pos)

    return size, atom_type, header_size


def find_atom(f, target, start=0, end=None):
    """Find an atom by type within a range."""
    if end is None:
        f.seek(0, 2)
        end = f.tell()

    f.seek(start)
    while f.tell() < end:
        pos = f.tell()
        size, atom_type, header_size = read_atom_header(f)
        if size is None:
            break
        if atom_type == target:
            return pos, size, header_size
        if size == 0:
            break
        f.seek(pos + size)
    return None


# ============================================================================
# AudioSpecificConfig Parsing
# ============================================================================

def parse_audio_specific_config(asc):
    """Parse AAC AudioSpecificConfig."""
    if len(asc) < 2:
        return {}

    bits = ''.join(format(b, '08b') for b in asc)
    result = {}
    bit_pos = 0

    # audioObjectType (5 bits, can be extended)
    aot = int(bits[bit_pos:bit_pos+5], 2)
    bit_pos += 5
    if aot == 31:
        aot = 32 + int(bits[bit_pos:bit_pos+6], 2)
        bit_pos += 6
    result['audio_object_type'] = aot
    result['aot_name'] = AOT_NAMES.get(aot, f'Unknown ({aot})')

    # samplingFrequencyIndex (4 bits)
    sf_idx = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4

    if sf_idx == 15:
        result['sample_rate'] = int(bits[bit_pos:bit_pos+24], 2)
        bit_pos += 24
    elif sf_idx < len(SAMPLE_RATES):
        result['sample_rate'] = SAMPLE_RATES[sf_idx]
    result['sf_index'] = sf_idx

    # channelConfiguration (4 bits)
    ch_cfg = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    result['channel_config'] = ch_cfg

    ch_names = {0: 'PCE-defined', 1: 'Mono', 2: 'Stereo', 3: '3.0',
                4: '4.0', 5: '5.0', 6: '5.1', 7: '7.1'}
    result['channel_config_name'] = ch_names.get(ch_cfg, f'Unknown ({ch_cfg})')

    # If channel config is 0, parse GASpecificConfig and PCE
    if ch_cfg == 0 and aot in [1, 2, 3, 4]:
        # frame_length_flag (unused but required for bit positioning)
        bit_pos += 1
        depends_on_core_coder = int(bits[bit_pos], 2)
        bit_pos += 1
        if depends_on_core_coder:
            bit_pos += 14
        # extension_flag (unused but required for bit positioning)
        bit_pos += 1

        pce = parse_program_config_element_bits(bits, bit_pos)
        result['pce'] = pce
        result['total_channels'] = pce.get('total_channels', 0)

    return result


def parse_program_config_element_bits(bits, bit_pos):
    """Parse Program Config Element from bit string."""
    pce = {}

    pce['element_instance_tag'] = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    pce['object_type'] = int(bits[bit_pos:bit_pos+2], 2)
    bit_pos += 2
    pce['sampling_frequency_index'] = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4

    num_front = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    num_side = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    num_back = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    num_lfe = int(bits[bit_pos:bit_pos+2], 2)
    bit_pos += 2
    num_assoc_data = int(bits[bit_pos:bit_pos+3], 2)
    bit_pos += 3
    num_valid_cc = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4

    pce['num_front'] = num_front
    pce['num_side'] = num_side
    pce['num_back'] = num_back
    pce['num_lfe'] = num_lfe
    pce['num_assoc_data'] = num_assoc_data
    pce['num_valid_cc'] = num_valid_cc

    # Skip mixdown flags
    if int(bits[bit_pos], 2):
        bit_pos += 5
    else:
        bit_pos += 1
    if int(bits[bit_pos], 2):
        bit_pos += 5
    else:
        bit_pos += 1
    if int(bits[bit_pos], 2):
        bit_pos += 4
    else:
        bit_pos += 1

    # Count channels and collect element info
    total_channels = 0
    elements = []

    for _ in range(num_front):
        is_cpe = int(bits[bit_pos], 2)
        bit_pos += 1
        tag = int(bits[bit_pos:bit_pos+4], 2)
        bit_pos += 4
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('front', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_side):
        is_cpe = int(bits[bit_pos], 2)
        bit_pos += 1
        tag = int(bits[bit_pos:bit_pos+4], 2)
        bit_pos += 4
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('side', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_back):
        is_cpe = int(bits[bit_pos], 2)
        bit_pos += 1
        tag = int(bits[bit_pos:bit_pos+4], 2)
        bit_pos += 4
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('back', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_lfe):
        tag = int(bits[bit_pos:bit_pos+4], 2)
        bit_pos += 4
        total_channels += 1
        elements.append(('lfe', 'SCE', tag, 1))

    pce['total_channels'] = total_channels
    pce['elements'] = elements

    return pce


def parse_esds(esds_data):
    """Parse the esds (Elementary Stream Descriptor) box."""
    result = {}
    i = 4  # Skip version + flags

    while i < len(esds_data):
        tag = esds_data[i]
        i += 1

        size = 0
        for _ in range(4):
            if i >= len(esds_data):
                break
            b = esds_data[i]
            i += 1
            size = (size << 7) | (b & 0x7f)
            if b & 0x80 == 0:
                break

        if tag == 0x03:  # ES_Descriptor
            if i + 3 <= len(esds_data):
                result['es_id'] = (esds_data[i] << 8) | esds_data[i+1]
                i += 3
            continue

        if tag == 0x04:  # DecoderConfigDescriptor
            if i + 13 <= len(esds_data):
                result['object_type'] = esds_data[i]
                result['max_bitrate'] = struct.unpack('>I', esds_data[i+5:i+9])[0]
                result['avg_bitrate'] = struct.unpack('>I', esds_data[i+9:i+13])[0]
                i += 13
            continue

        if tag == 0x05:  # DecoderSpecificInfo (ASC)
            asc = esds_data[i:i+size]
            result['audio_specific_config'] = asc
            result['asc_parsed'] = parse_audio_specific_config(asc)
            i += size
        else:
            i += size

    return result


# ============================================================================
# ADTS Frame Parsing
# ============================================================================

def parse_adts_frames(data, max_frames=10):
    """Parse ADTS frames from raw data."""
    frames = []
    pos = 0

    while pos < len(data) - 7 and len(frames) < max_frames:
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue

        header = data[pos:pos+7]
        protection_absent = header[1] & 1
        profile = (header[2] >> 6) & 3
        sf_idx = (header[2] >> 2) & 0xF
        ch_cfg = ((header[2] & 1) << 2) | ((header[3] >> 6) & 3)
        frame_len = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)

        header_size = 7 if protection_absent else 9

        if frame_len < header_size or pos + frame_len > len(data):
            pos += 1
            continue

        raw_start = pos + header_size
        raw_data = data[raw_start:raw_start+50]

        frames.append({
            'index': len(frames),
            'offset': pos,
            'length': frame_len,
            'header_size': header_size,
            'profile': profile,
            'sf_idx': sf_idx,
            'ch_cfg': ch_cfg,
            'raw_offset': raw_start,
            'raw_data': raw_data
        })
        pos += frame_len

    return frames


def count_total_frames(data):
    """Count total ADTS frames in data."""
    pos = 0
    count = 0
    while pos < len(data) - 7:
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue
        header = data[pos:pos+7]
        frame_len = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)
        if frame_len < 7:
            pos += 1
            continue
        count += 1
        pos += frame_len
    return count


def parse_raw_data_block(raw_data):
    """Parse syntactic elements from raw data block."""
    if len(raw_data) < 1:
        return None

    br = BitReader(raw_data)
    elem_id = br.read_bits(3)

    if elem_id is None or elem_id >= len(ELEMENT_NAMES):
        return None

    result = {'element': ELEMENT_NAMES[elem_id], 'element_id': elem_id}

    if elem_id == 5:  # PCE
        result['pce'] = parse_pce_from_bitreader(br)
    elif elem_id in [0, 1]:  # SCE, CPE
        result['instance_tag'] = br.read_bits(4)

    return result


def parse_pce_from_bitreader(br):
    """Parse PCE from BitReader."""
    pce = {}
    pce['element_instance_tag'] = br.read_bits(4)
    pce['object_type'] = br.read_bits(2)
    pce['sampling_frequency_index'] = br.read_bits(4)

    num_front = br.read_bits(4)
    num_side = br.read_bits(4)
    num_back = br.read_bits(4)
    num_lfe = br.read_bits(2)
    br.read_bits(3)  # num_assoc_data (unused)
    br.read_bits(4)  # num_valid_cc (unused)

    pce['num_front'] = num_front
    pce['num_side'] = num_side
    pce['num_back'] = num_back
    pce['num_lfe'] = num_lfe

    # Skip mixdown flags
    if br.read_bits(1):
        br.read_bits(4)
    if br.read_bits(1):
        br.read_bits(4)
    if br.read_bits(1):
        br.read_bits(3)

    elements = []
    total_channels = 0

    for _ in range(num_front):
        is_cpe = br.read_bits(1)
        tag = br.read_bits(4)
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('front', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_side):
        is_cpe = br.read_bits(1)
        tag = br.read_bits(4)
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('side', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_back):
        is_cpe = br.read_bits(1)
        tag = br.read_bits(4)
        ch = 2 if is_cpe else 1
        total_channels += ch
        elements.append(('back', 'CPE' if is_cpe else 'SCE', tag, ch))

    for _ in range(num_lfe):
        tag = br.read_bits(4)
        total_channels += 1
        elements.append(('lfe', 'SCE', tag, 1))

    pce['elements'] = elements
    pce['total_channels'] = total_channels

    return pce


# ============================================================================
# Container Analysis
# ============================================================================

def analyze_container(filepath):
    """Analyze MP4 container structure."""
    print("\n" + "=" * 60)
    print("CONTAINER ANALYSIS")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(0)

        print(f"\nFile: {filepath}")
        print(f"Size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")

        # List top-level atoms
        print("\nTop-level atoms:")
        pos = 0
        while pos < file_size:
            f.seek(pos)
            size, atom_type, _ = read_atom_header(f)
            if size is None or size == 0:
                break
            name = atom_type.decode('latin1', errors='replace')
            print(f"  {name:6s} offset={pos:>10,}  size={size:>12,}")
            pos += size

        # Find and parse moov/trak/mdia/stsd
        moov = find_atom(f, b'moov')
        if not moov:
            print("\nERROR: No moov atom found!")
            return None

        moov_pos, moov_size, _ = moov
        trak = find_atom(f, b'trak', moov_pos + 8, moov_pos + moov_size)
        if not trak:
            print("\nERROR: No trak atom found!")
            return None

        trak_pos, trak_size, _ = trak
        mdia = find_atom(f, b'mdia', trak_pos + 8, trak_pos + trak_size)
        if not mdia:
            return None

        mdia_pos, mdia_size, _ = mdia

        # Get duration from mdhd
        mdhd = find_atom(f, b'mdhd', mdia_pos + 8, mdia_pos + mdia_size)
        if mdhd:
            mdhd_pos, mdhd_size, _ = mdhd
            f.seek(mdhd_pos + 8)
            mdhd_data = f.read(mdhd_size - 8)
            version = mdhd_data[0]
            if version == 0:
                timescale = struct.unpack('>I', mdhd_data[12:16])[0]
                duration = struct.unpack('>I', mdhd_data[16:20])[0]
            else:
                timescale = struct.unpack('>I', mdhd_data[20:24])[0]
                duration = struct.unpack('>Q', mdhd_data[24:32])[0]
            duration_secs = duration / timescale if timescale else 0
            print(f"\nDuration: {duration_secs:.2f}s ({duration_secs/60:.1f} min)")

        # Find stsd
        minf = find_atom(f, b'minf', mdia_pos + 8, mdia_pos + mdia_size)
        if not minf:
            return None
        minf_pos, minf_size, _ = minf

        stbl = find_atom(f, b'stbl', minf_pos + 8, minf_pos + minf_size)
        if not stbl:
            return None
        stbl_pos, stbl_size, _ = stbl

        stsd = find_atom(f, b'stsd', stbl_pos + 8, stbl_pos + stbl_size)
        if not stsd:
            return None

        stsd_pos, stsd_size, _ = stsd
        f.seek(stsd_pos)
        stsd_data = f.read(stsd_size)

        # Parse mp4a sample description
        offset = 16
        entry_type = stsd_data[offset+4:offset+8].decode('ascii', errors='replace')

        if entry_type != 'mp4a':
            print(f"\nUnexpected entry type: {entry_type}")
            return None

        mp4a_offset = offset + 8 + 6  # Skip reserved
        mp4a_offset += 2  # data_ref_index
        mp4a_offset += 8  # reserved
        channels = struct.unpack('>H', stsd_data[mp4a_offset:mp4a_offset+2])[0]
        mp4a_offset += 2
        sample_size = struct.unpack('>H', stsd_data[mp4a_offset:mp4a_offset+2])[0]
        mp4a_offset += 2
        mp4a_offset += 4  # reserved
        sample_rate = struct.unpack('>I', stsd_data[mp4a_offset:mp4a_offset+4])[0] >> 16

        print("\nAudio Format: mp4a")
        print(f"  Channels (header): {channels}")
        print(f"  Sample Rate: {sample_rate} Hz")
        print(f"  Sample Size: {sample_size} bits")

        # Find and parse esds
        entry_size = struct.unpack('>I', stsd_data[offset:offset+4])[0]
        esds_offset = offset + 8 + 28

        while esds_offset < offset + entry_size:
            box_size = struct.unpack('>I', stsd_data[esds_offset:esds_offset+4])[0]
            box_type = stsd_data[esds_offset+4:esds_offset+8].decode('ascii', errors='replace')

            if box_type == 'esds':
                esds_content = stsd_data[esds_offset+8:esds_offset+box_size]
                return parse_esds(esds_content)

            esds_offset += box_size

        return None


def print_audio_config(esds_info):
    """Print audio configuration from esds."""
    if not esds_info:
        return

    print("\n" + "=" * 60)
    print("AUDIO CONFIGURATION")
    print("=" * 60)

    print(f"\nBitrate: {esds_info.get('avg_bitrate', 0) / 1000:.0f} kbps")

    if 'audio_specific_config' in esds_info:
        print(f"ASC (hex): {esds_info['audio_specific_config'].hex()}")

    if 'asc_parsed' in esds_info:
        asc = esds_info['asc_parsed']
        print("\nAudioSpecificConfig:")
        print(f"  Audio Object Type: {asc.get('aot_name', 'Unknown')}")
        print(f"  Sample Rate: {asc.get('sample_rate', 'Unknown')} Hz")
        print(f"  Channel Config: {asc.get('channel_config_name', 'Unknown')}")

        if 'pce' in asc:
            pce = asc['pce']
            print("\nProgram Config Element:")
            print(f"  Total Channels: {pce.get('total_channels', 0)}")
            print(f"  Front elements: {pce.get('num_front', 0)}")
            print(f"  Side elements: {pce.get('num_side', 0)}")
            print(f"  Back elements: {pce.get('num_back', 0)}")
            print(f"  LFE elements: {pce.get('num_lfe', 0)}")

            if 'elements' in pce:
                print("\n  Channel Elements:")
                for pos, elem_type, tag, ch in pce['elements']:
                    print(f"    {pos:5s}: {elem_type} tag={tag} ({ch}ch)")


# ============================================================================
# ADTS Stream Analysis
# ============================================================================

def analyze_adts_stream(filepath, max_frames=10):
    """Analyze ADTS stream extracted from stems file."""
    print("\n" + "=" * 60)
    print("ADTS FRAME ANALYSIS")
    print("=" * 60)

    # Extract ADTS stream using ffmpeg
    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        result = subprocess.run([
            'ffmpeg', '-y', '-v', 'error',
            '-i', str(filepath),
            '-c:a', 'copy', '-f', 'adts',
            tmp_path
        ], capture_output=True, text=True, check=False)

        if result.returncode != 0:
            print(f"Failed to extract ADTS: {result.stderr}")
            return None

        with open(tmp_path, 'rb') as f:
            data = f.read()

        print(f"\nExtracted ADTS size: {len(data):,} bytes")

        # Count total frames
        total = count_total_frames(data)
        print(f"Total frames: {total}")
        print(f"Expected duration: {total * 1024 / 44100:.1f}s")

        # Parse individual frames
        frames = parse_adts_frames(data, max_frames)

        print(f"\nFirst {len(frames)} frames:")
        print("-" * 60)

        # Collect valid element tags from PCE
        pce_tags = set()

        for frame in frames:
            parsed = parse_raw_data_block(frame['raw_data'])

            line = (f"Frame {frame['index']:3d}: "
                    f"offset={frame['offset']:>8,}  len={frame['length']:>4}")

            if parsed:
                elem = parsed['element']
                line += f"  {elem}"

                if 'instance_tag' in parsed:
                    tag = parsed['instance_tag']
                    line += f" tag={tag}"

                    # Check if tag is valid
                    if pce_tags and (parsed['element_id'], tag) not in pce_tags:
                        line += " ❌ INVALID"

                if 'pce' in parsed:
                    pce = parsed['pce']
                    line += f" ({pce['total_channels']}ch)"
                    # Record valid tags
                    for _, elem_type, tag, _ in pce.get('elements', []):
                        elem_id = 1 if elem_type == 'CPE' else 0
                        pce_tags.add((elem_id, tag))

            print(line)

        return frames

    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ============================================================================
# XOR Encryption Analysis
# ============================================================================

def analyze_xor_patterns(filepath):
    """Analyze potential XOR encryption patterns."""
    print("\n" + "=" * 60)
    print("XOR ENCRYPTION ANALYSIS")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as tmp:
        tmp_path = tmp.name

    try:
        subprocess.run([
            'ffmpeg', '-y', '-v', 'error',
            '-i', str(filepath),
            '-c:a', 'copy', '-f', 'adts',
            tmp_path
        ], capture_output=True, check=False)

        with open(tmp_path, 'rb') as f:
            data = f.read()

        frames = parse_adts_frames(data, 20)

        if len(frames) < 2:
            print("Not enough frames for analysis")
            return

        print("\nFrame 0 contains PCE (valid reference)")

        frame1 = frames[1]
        first_byte = frame1['raw_data'][0]

        # Calculate XOR needed to get CPE tag=0
        expected = 0x20  # CPE tag=0: 001 0000 0
        xor_key = first_byte ^ expected

        print("\nFrame 1 analysis:")
        print(f"  First byte: 0x{first_byte:02x}")
        print(f"  Expected (CPE tag=0): 0x{expected:02x}")
        print(f"  XOR key needed: 0x{xor_key:02x}")

        print("\nRequired XOR values for each frame to produce CPE tag=0:")
        print("-" * 40)

        xor_values = []
        for frame in frames[1:16]:
            fb = frame['raw_data'][0]
            xor_val = fb ^ expected
            xor_values.append(xor_val)
            print(f"  Frame {frame['index']:2d}: 0x{fb:02x} → XOR 0x{xor_val:02x}")

        # Check for patterns
        print("\nPattern analysis:")

        # Check linear
        diffs = [xor_values[i+1] - xor_values[i] for i in range(len(xor_values)-1)]
        if len(set(diffs)) == 1:
            print(f"  Linear pattern: step={diffs[0]}")
        else:
            print("  No linear pattern")

        # Check XOR with frame index
        print("\n  Checking XOR key = frame_index:")
        for i, frame in enumerate(frames[1:6], 1):
            fb = frame['raw_data'][0]
            result = fb ^ i
            elem_id = (result >> 5) & 7
            tag = (result >> 1) & 0xF
            print(f"    Frame {i}: 0x{fb:02x} XOR {i} = {ELEMENT_NAMES[elem_id]} tag={tag}")

    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ============================================================================
# Main Entry Point
# ============================================================================

def find_stems_file():
    """Find a stems file to analyze in common locations."""
    # Check command line
    for arg in sys.argv[1:]:
        if arg.endswith('.stems') and Path(arg).exists():
            return arg

    # Check stems directory
    stems_dir = Path('stems')
    if stems_dir.exists():
        files = list(stems_dir.glob('*.stems'))
        if files:
            return files[0]

    # Check current directory
    files = list(Path('.').glob('*.stems'))
    if files:
        return files[0]

    return None


def main():
    """Main entry point for the analyzer."""
    print("=" * 60)
    print("ENGINE DJ STEMS ANALYZER")
    print("=" * 60)

    # Parse options
    max_frames = 10
    do_xor = '--xor' in sys.argv or '--all' in sys.argv

    for i, arg in enumerate(sys.argv):
        if arg == '--frames' and i + 1 < len(sys.argv):
            try:
                max_frames = int(sys.argv[i + 1])
            except ValueError:
                pass

    # Find file
    filepath = find_stems_file()

    if not filepath:
        print("\nUsage: python analyze.py <file.stems> [options]")
        print("\nOptions:")
        print("  --frames N    Number of frames to analyze (default: 10)")
        print("  --xor         Include XOR encryption analysis")
        print("  --all         Run all analyses")
        print("\nNo .stems file found. Place files in ./stems/ directory")
        sys.exit(1)

    # Run analyses
    esds_info = analyze_container(filepath)

    if esds_info:
        print_audio_config(esds_info)

    analyze_adts_stream(filepath, max_frames)

    if do_xor:
        analyze_xor_patterns(filepath)

    print("\n" + "=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print("""
The AAC bitstream contains invalid element tags that don't match
the PCE definition. This suggests the audio data is encrypted or
uses a proprietary codec.

Standard decoders (ffmpeg, faad2, libfdk-aac) cannot decode this format.
""")


if __name__ == '__main__':
    main()
