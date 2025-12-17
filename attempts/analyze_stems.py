#!/usr/bin/env python3
"""
Analyze Engine DJ stem files (.stems) to understand their format
and extract individual stem tracks.
"""

import struct
import sys
from pathlib import Path


def read_atom_header(f):
    """Read an MP4 atom header, returns (size, type, header_size)"""
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
    """Find an atom by type within a range"""
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


def parse_esds(esds_data):
    """Parse the esds (Elementary Stream Descriptor) box"""
    result = {}

    # Skip version (1) + flags (3)
    i = 4

    while i < len(esds_data):
        tag = esds_data[i]
        i += 1

        # Read expandable size
        size = 0
        for _ in range(4):
            if i >= len(esds_data):
                break
            b = esds_data[i]
            i += 1
            size = (size << 7) | (b & 0x7f)
            if b & 0x80 == 0:
                break

        # content_start (unused)
        _ = i

        if tag == 0x03:  # ES_Descriptor
            if i + 3 <= len(esds_data):
                result['es_id'] = (esds_data[i] << 8) | esds_data[i+1]
                result['es_flags'] = esds_data[i+2]
                i += 3
            continue  # Parse nested descriptors

        if tag == 0x04:  # DecoderConfigDescriptor
            if i + 13 <= len(esds_data):
                result['object_type'] = esds_data[i]
                result['stream_type'] = (esds_data[i+1] >> 2) & 0x3f
                result['buffer_size'] = (esds_data[i+2] << 16) | (esds_data[i+3] << 8) | esds_data[i+4]
                result['max_bitrate'] = struct.unpack('>I', esds_data[i+5:i+9])[0]
                result['avg_bitrate'] = struct.unpack('>I', esds_data[i+9:i+13])[0]
                i += 13
            continue  # Parse nested

        if tag == 0x05:  # DecoderSpecificInfo (AudioSpecificConfig)
            asc = esds_data[i:i+size]
            result['audio_specific_config'] = asc
            result['asc_parsed'] = parse_audio_specific_config(asc)
            i += size

        if tag == 0x06:  # SLConfigDescriptor
            i += size
        else:
            i += size

    return result


def parse_audio_specific_config(asc):
    """Parse AAC AudioSpecificConfig"""
    if len(asc) < 2:
        return {}

    # Convert to bit string for easier parsing
    bits = ''.join(format(b, '08b') for b in asc)

    result = {}
    bit_pos = 0

    # audioObjectType (5 bits, can be extended)
    aot = int(bits[bit_pos:bit_pos+5], 2)
    bit_pos += 5
    if aot == 31:  # Extended
        aot = 32 + int(bits[bit_pos:bit_pos+6], 2)
        bit_pos += 6
    result['audio_object_type'] = aot
    result['aot_name'] = {
        1: 'AAC Main', 2: 'AAC LC', 3: 'AAC SSR', 4: 'AAC LTP',
        5: 'SBR', 6: 'AAC Scalable', 29: 'PS'
    }.get(aot, f'Unknown ({aot})')

    # samplingFrequencyIndex (4 bits)
    sf_idx = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4

    sf_table = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                16000, 12000, 11025, 8000, 7350]

    if sf_idx == 15:  # Explicit frequency
        result['sample_rate'] = int(bits[bit_pos:bit_pos+24], 2)
        bit_pos += 24
    elif sf_idx < len(sf_table):
        result['sample_rate'] = sf_table[sf_idx]
    result['sf_index'] = sf_idx

    # channelConfiguration (4 bits)
    ch_cfg = int(bits[bit_pos:bit_pos+4], 2)
    bit_pos += 4
    result['channel_config'] = ch_cfg

    ch_names = {
        0: 'Defined in PCE', 1: 'Mono', 2: 'Stereo', 3: '3.0',
        4: '4.0', 5: '5.0', 6: '5.1', 7: '7.1'
    }
    result['channel_config_name'] = ch_names.get(ch_cfg, f'Unknown ({ch_cfg})')

    # If channel config is 0, there's a Program Config Element
    if ch_cfg == 0 and aot in [1, 2, 3, 4]:  # GASpecificConfig follows
        # GASpecificConfig
        frame_length_flag = int(bits[bit_pos], 2)
        bit_pos += 1
        depends_on_core_coder = int(bits[bit_pos], 2)
        bit_pos += 1
        if depends_on_core_coder:
            bit_pos += 14  # coreCoderDelay
        extension_flag = int(bits[bit_pos], 2)
        bit_pos += 1

        result['frame_length_flag'] = frame_length_flag
        result['depends_on_core_coder'] = depends_on_core_coder
        result['extension_flag'] = extension_flag

        # Program Config Element follows
        pce = parse_program_config_element(bits, bit_pos)
        result['pce'] = pce
        result['total_channels'] = pce.get('total_channels', 0)

    return result


def parse_program_config_element(bits, bit_pos):
    """Parse AAC Program Config Element"""
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

    pce['num_front_channel_elements'] = num_front
    pce['num_side_channel_elements'] = num_side
    pce['num_back_channel_elements'] = num_back
    pce['num_lfe_channel_elements'] = num_lfe
    pce['num_assoc_data_elements'] = num_assoc_data
    pce['num_valid_cc_elements'] = num_valid_cc

    # Skip some flags
    mono_mixdown_present = int(bits[bit_pos], 2)
    bit_pos += 1
    if mono_mixdown_present:
        bit_pos += 4

    stereo_mixdown_present = int(bits[bit_pos], 2)
    bit_pos += 1
    if stereo_mixdown_present:
        bit_pos += 4

    matrix_mixdown_idx_present = int(bits[bit_pos], 2)
    bit_pos += 1
    if matrix_mixdown_idx_present:
        bit_pos += 3

    # Count actual channels
    total_channels = 0

    # Front channels
    for _ in range(num_front):
        is_cpe = int(bits[bit_pos], 2)  # 1 = channel pair (stereo), 0 = single
        bit_pos += 1
        bit_pos += 4  # element_tag_select
        total_channels += 2 if is_cpe else 1

    # Side channels
    for _ in range(num_side):
        is_cpe = int(bits[bit_pos], 2)
        bit_pos += 1
        bit_pos += 4
        total_channels += 2 if is_cpe else 1

    # Back channels
    for _ in range(num_back):
        is_cpe = int(bits[bit_pos], 2)
        bit_pos += 1
        bit_pos += 4
        total_channels += 2 if is_cpe else 1

    # LFE channels
    for _ in range(num_lfe):
        bit_pos += 4
        total_channels += 1

    pce['total_channels'] = total_channels

    return pce


def analyze_stem_file(filepath):
    """Analyze an Engine DJ stem file"""
    print(f"\n{'='*60}")
    print(f"Analyzing: {filepath}")
    print(f"{'='*60}")

    with open(filepath, 'rb') as f:
        # Get file size
        f.seek(0, 2)
        file_size = f.tell()
        f.seek(0)

        print(f"\nFile size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")

        # List top-level atoms
        print("\nTop-level atoms:")
        pos = 0
        atoms = []
        while pos < file_size:
            f.seek(pos)
            size, atom_type, _header_size = read_atom_header(f)
            if size is None or size == 0:
                break
            atom_name = atom_type.decode('latin1', errors='replace')
            atoms.append((pos, size, atom_name))
            print(f"  {atom_name} at offset {pos}, size {size:,}")
            pos += size

        # Find and parse moov
        moov = find_atom(f, b'moov')
        if not moov:
            print("ERROR: No moov atom found!")
            return

        moov_pos, moov_size, _ = moov
        print(f"\nParsing moov atom at {moov_pos}...")

        # Find trak
        trak = find_atom(f, b'trak', moov_pos + 8, moov_pos + moov_size)
        if not trak:
            print("ERROR: No trak atom found!")
            return

        trak_pos, trak_size, _ = trak

        # Find mdia -> minf -> stbl -> stsd
        mdia = find_atom(f, b'mdia', trak_pos + 8, trak_pos + trak_size)
        if mdia:
            mdia_pos, mdia_size, _ = mdia
            minf = find_atom(f, b'minf', mdia_pos + 8, mdia_pos + mdia_size)
            if minf:
                minf_pos, minf_size, _ = minf
                stbl = find_atom(f, b'stbl', minf_pos + 8, minf_pos + minf_size)
                if stbl:
                    stbl_pos, stbl_size, _ = stbl
                    stsd = find_atom(f, b'stsd', stbl_pos + 8, stbl_pos + stbl_size)
                    if stsd:
                        stsd_pos, stsd_size, _ = stsd
                        f.seek(stsd_pos)
                        stsd_data = f.read(stsd_size)

                        print("\nAudio Sample Description:")

                        # Parse stsd
                        # header (8) + version/flags (4) + entry_count (4)
                        entry_count = struct.unpack('>I', stsd_data[12:16])[0]
                        print(f"  Entry count: {entry_count}")

                        # Parse mp4a entry
                        offset = 16
                        entry_size = struct.unpack('>I', stsd_data[offset:offset+4])[0]
                        entry_type = stsd_data[offset+4:offset+8].decode('ascii', errors='replace')
                        print(f"  Entry type: {entry_type}, size: {entry_size}")

                        if entry_type == 'mp4a':
                            # mp4a structure
                            mp4a_offset = offset + 8
                            mp4a_offset += 6  # reserved
                            _data_ref_index = struct.unpack('>H', stsd_data[mp4a_offset:mp4a_offset+2])[0]
                            mp4a_offset += 2
                            mp4a_offset += 8  # reserved
                            channels = struct.unpack('>H', stsd_data[mp4a_offset:mp4a_offset+2])[0]
                            mp4a_offset += 2
                            sample_size = struct.unpack('>H', stsd_data[mp4a_offset:mp4a_offset+2])[0]
                            mp4a_offset += 2
                            mp4a_offset += 4  # reserved
                            sample_rate = struct.unpack('>I', stsd_data[mp4a_offset:mp4a_offset+4])[0] >> 16

                            print(f"  Channels (mp4a header): {channels}")
                            print(f"  Sample size: {sample_size} bits")
                            print(f"  Sample rate: {sample_rate} Hz")

                            # Find esds box
                            esds_offset = offset + 8 + 28
                            while esds_offset < offset + entry_size:
                                box_size = struct.unpack('>I', stsd_data[esds_offset:esds_offset+4])[0]
                                box_type = stsd_data[esds_offset+4:esds_offset+8].decode('ascii', errors='replace')

                                if box_type == 'esds':
                                    esds_content = stsd_data[esds_offset+8:esds_offset+box_size]
                                    esds_info = parse_esds(esds_content)

                                    print("\n  ESDS Info:")
                                    print(f"    Object Type: {esds_info.get('object_type', 'N/A'):#x}")
                                    print(f"    Max Bitrate: {esds_info.get('max_bitrate', 0):,} bps")
                                    print(f"    Avg Bitrate: {esds_info.get('avg_bitrate', 0):,} bps")

                                    if 'asc_parsed' in esds_info:
                                        asc = esds_info['asc_parsed']
                                        print("\n  AudioSpecificConfig:")
                                        print(f"    Audio Object Type: {asc.get('aot_name', 'Unknown')}")
                                        print(f"    Sample Rate: {asc.get('sample_rate', 'Unknown')} Hz")
                                        print(f"    Channel Config: {asc.get('channel_config_name', 'Unknown')}")

                                        if 'pce' in asc:
                                            pce = asc['pce']
                                            print("\n  Program Config Element:")
                                            print(f"    Front channel elements: {pce.get('num_front_channel_elements', 0)}")
                                            print(f"    Side channel elements: {pce.get('num_side_channel_elements', 0)}")
                                            print(f"    Back channel elements: {pce.get('num_back_channel_elements', 0)}")
                                            print(f"    LFE channel elements: {pce.get('num_lfe_channel_elements', 0)}")
                                            print(f"    Total channels: {pce.get('total_channels', 0)}")

                                    if 'audio_specific_config' in esds_info:
                                        print("\n  Raw ASC hex: " + esds_info['audio_specific_config'].hex())

                                esds_offset += box_size

        # Find mdhd for duration info
        if mdia:
            mdhd = find_atom(f, b'mdhd', mdia_pos + 8, mdia_pos + mdia_size)
            if mdhd:
                mdhd_pos, mdhd_size, _ = mdhd
                f.seek(mdhd_pos + 8)  # Skip header
                mdhd_data = f.read(mdhd_size - 8)
                version = mdhd_data[0]

                if version == 0:
                    timescale = struct.unpack('>I', mdhd_data[12:16])[0]
                    duration = struct.unpack('>I', mdhd_data[16:20])[0]
                else:
                    timescale = struct.unpack('>I', mdhd_data[20:24])[0]
                    duration = struct.unpack('>Q', mdhd_data[24:32])[0]

                duration_secs = duration / timescale if timescale else 0
                print(f"\n  Duration: {duration_secs:.2f} seconds ({duration_secs/60:.2f} minutes)")


def analyze_adts_header(data):
    """Analyze ADTS frame header"""
    if len(data) < 7:
        return None

    # ADTS header is 7 bytes (without CRC) or 9 bytes (with CRC)
    # Syncword: 12 bits (0xFFF)
    # ID: 1 bit (0 = MPEG-4, 1 = MPEG-2)
    # Layer: 2 bits (always 00)
    # Protection_absent: 1 bit (1 = no CRC)
    # Profile: 2 bits (00 = Main, 01 = LC, 10 = SSR, 11 = reserved)
    # Sampling_frequency_index: 4 bits
    # Private_bit: 1 bit
    # Channel_configuration: 3 bits
    # ...

    bits = ''.join(format(b, '08b') for b in data[:7])

    result = {}
    result['syncword'] = bits[0:12]
    result['id'] = int(bits[12], 2)  # 0=MPEG-4, 1=MPEG-2
    result['layer'] = int(bits[13:15], 2)
    result['protection_absent'] = int(bits[15], 2)
    result['profile'] = int(bits[16:18], 2)
    result['sampling_frequency_index'] = int(bits[18:22], 2)
    result['private_bit'] = int(bits[22], 2)
    result['channel_configuration'] = int(bits[23:26], 2)
    result['original_copy'] = int(bits[26], 2)
    result['home'] = int(bits[27], 2)

    # Variable header
    result['copyright_id_bit'] = int(bits[28], 2)
    result['copyright_id_start'] = int(bits[29], 2)
    result['frame_length'] = int(bits[30:43], 2)
    result['buffer_fullness'] = int(bits[43:54], 2)
    result['number_of_raw_data_blocks'] = int(bits[54:56], 2)

    sf_table = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                16000, 12000, 11025, 8000, 7350]
    if result['sampling_frequency_index'] < len(sf_table):
        result['sample_rate'] = sf_table[result['sampling_frequency_index']]

    profile_names = ['Main', 'LC', 'SSR', 'Reserved']
    result['profile_name'] = profile_names[result['profile']]

    return result


def analyze_aac_stream(filepath):
    """Analyze raw AAC/ADTS stream"""
    print(f"\n{'='*60}")
    print(f"Analyzing AAC stream: {filepath}")
    print(f"{'='*60}")

    with open(filepath, 'rb') as f:
        data = f.read(100)

    # Check for ADTS syncword
    if data[0:2] == b'\xff\xf1' or data[0:2] == b'\xff\xf9':
        print("Format: ADTS")
        header = analyze_adts_header(data)
        if header:
            print(f"  MPEG ID: {'MPEG-2' if header['id'] else 'MPEG-4'}")
            print(f"  Profile: {header['profile_name']}")
            print(f"  Sample rate: {header.get('sample_rate', 'Unknown')} Hz")
            print(f"  Channel config: {header['channel_configuration']}")
            print(f"  Frame length: {header['frame_length']} bytes")
            print(f"  Raw data blocks: {header['number_of_raw_data_blocks'] + 1}")
    else:
        print(f"Unknown format, first bytes: {data[:16].hex()}")


def main():
    """Entry point for analyzing stems or a provided AAC file."""

    stems_dir = Path(__file__).parent / 'stems'

    # Check command line args for AAC file analysis
    if len(sys.argv) > 1 and sys.argv[1].endswith('.aac'):
        analyze_aac_stream(sys.argv[1])
        return

    if not stems_dir.exists():
        print(f"Stems directory not found: {stems_dir}")
        return

    stem_files = list(stems_dir.glob('*.stems'))

    if not stem_files:
        print("No .stems files found!")
        return

    print(f"Found {len(stem_files)} stem file(s)")

    for stem_file in stem_files:
        analyze_stem_file(stem_file)


if __name__ == '__main__':
    main()
