#!/usr/bin/env python3
"""
Analyze ADTS AAC frames to understand the structure and find PCE issues.
"""

import sys
import subprocess
import tempfile
import os


SAMPLE_RATES = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                16000, 12000, 11025, 8000, 7350]


def parse_adts_header(data: bytes, offset: int) -> dict:
    """Parse ADTS header at given offset."""
    if len(data) < offset + 7:
        return None
    if data[offset] != 0xFF or (data[offset+1] & 0xF0) != 0xF0:
        return None

    h = data[offset:offset+7]

    mpeg_version = (h[1] >> 3) & 1  # 0=MPEG-4, 1=MPEG-2
    protection_absent = h[1] & 1

    profile = (h[2] >> 6) & 3  # 0=Main, 1=LC, 2=SSR, 3=reserved
    sri = (h[2] >> 2) & 0xF
    cc = ((h[2] & 1) << 2) | ((h[3] >> 6) & 3)

    frame_len = ((h[3] & 3) << 11) | (h[4] << 3) | ((h[5] >> 5) & 7)
    buffer_fullness = ((h[5] & 0x1F) << 6) | ((h[6] >> 2) & 0x3F)
    num_raw_data_blocks = h[6] & 3

    header_size = 7 if protection_absent else 9

    return {
        'mpeg_version': 'MPEG-2' if mpeg_version else 'MPEG-4',
        'profile': ['Main', 'LC', 'SSR', 'Reserved'][profile],
        'profile_idx': profile,
        'sri': sri,
        'sample_rate': SAMPLE_RATES[sri] if sri < len(SAMPLE_RATES) else 'unknown',
        'channel_config': cc,
        'frame_length': frame_len,
        'header_size': header_size,
        'protection_absent': protection_absent,
        'buffer_fullness': buffer_fullness,
        'num_raw_data_blocks': num_raw_data_blocks,
    }


def parse_raw_data_block(data: bytes) -> dict:
    """
    Parse AAC raw_data_block to find elements.

    Raw data block contains:
    - id_syn_ele (3 bits): element type
      0: SCE (Single Channel Element)
      1: CPE (Channel Pair Element)
      2: CCE (Coupling Channel Element)
      3: LFE (Low Frequency Effects)
      4: DSE (Data Stream Element)
      5: PCE (Program Config Element)
      6: FIL (Fill Element)
      7: END (End)
    - element_instance_tag (4 bits) for SCE/CPE/CCE/LFE
    """
    if not data:
        return {}

    bits = ''.join(format(b, '08b') for b in data)

    elements = []
    bit_pos = 0

    element_names = ['SCE', 'CPE', 'CCE', 'LFE', 'DSE', 'PCE', 'FIL', 'END']

    while bit_pos + 3 <= len(bits):
        id_syn_ele = int(bits[bit_pos:bit_pos+3], 2)
        bit_pos += 3

        if id_syn_ele == 7:  # END
            elements.append({'type': 'END', 'bit_pos': bit_pos - 3})
            break

        elem = {
            'type': element_names[id_syn_ele],
            'bit_pos': bit_pos - 3,
        }

        if id_syn_ele in [0, 1, 2, 3]:  # SCE, CPE, CCE, LFE
            if bit_pos + 4 <= len(bits):
                elem['instance_tag'] = int(bits[bit_pos:bit_pos+4], 2)
                bit_pos += 4

        if id_syn_ele == 5:  # PCE
            # Parse PCE
            if bit_pos + 10 <= len(bits):
                elem['element_instance_tag'] = int(bits[bit_pos:bit_pos+4], 2)
                elem['object_type'] = int(bits[bit_pos+4:bit_pos+6], 2)
                elem['sampling_frequency_index'] = int(bits[bit_pos+6:bit_pos+10], 2)
                sri = elem['sampling_frequency_index']
                elem['sample_rate'] = SAMPLE_RATES[sri] if sri < len(SAMPLE_RATES) else 'unknown'

        elements.append(elem)

        # For now, just get first few elements
        if len(elements) >= 10:
            break

    return {'elements': elements}


def analyze_stems_file(stems_path: str):
    """Analyze a .stems file's AAC structure."""

    print(f"Analyzing: {stems_path}")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        adts_path = os.path.join(tmpdir, 'audio.aac')

        # Extract ADTS stream
        print("\nExtracting ADTS stream...")
        cmd = ['ffmpeg', '-y', '-i', stems_path, '-c:a', 'copy', '-vn', adts_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if not os.path.exists(adts_path):
            print(f"Failed to extract: {result.stderr}")
            return

        with open(adts_path, 'rb') as f:
            data = f.read()

        print(f"ADTS size: {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)")

        # Analyze frames
        print("\n" + "=" * 70)
        print("ADTS Frame Analysis")
        print("=" * 70)

        pos = 0
        frame_num = 0
        sri_mismatches = 0

        while pos < len(data) - 7 and frame_num < 10:
            info = parse_adts_header(data, pos)

            if info is None:
                # Try to find next sync
                pos += 1
                continue

            print(f"\nFrame {frame_num}:")
            print(f"  Position: {pos} (0x{pos:x})")
            print(f"  Length: {info['frame_length']} bytes")
            print(f"  ADTS Header: {info['mpeg_version']}, {info['profile']}")
            print(f"  Sample Rate Index: {info['sri']} ({info['sample_rate']} Hz)")
            print(f"  Channel Config: {info['channel_config']} (0=PCE in stream)")

            # Get frame payload
            payload_start = pos + info['header_size']
            payload_end = pos + info['frame_length']
            payload = data[payload_start:payload_end]

            print(f"  Payload: {len(payload)} bytes")
            print(f"  First 30 bytes: {payload[:30].hex()}")

            # Parse raw data block
            block_info = parse_raw_data_block(payload)
            if block_info.get('elements'):
                print("  Elements found:")
                for elem in block_info['elements'][:5]:
                    if elem['type'] == 'PCE':
                        pce_sri = elem.get('sampling_frequency_index', -1)
                        pce_sr = elem.get('sample_rate', 'unknown')
                        match = "✓" if pce_sri == info['sri'] else "✗ MISMATCH!"
                        print(f"    - {elem['type']}: SRI={pce_sri} ({pce_sr} Hz) {match}")
                        if pce_sri != info['sri']:
                            sri_mismatches += 1
                    elif 'instance_tag' in elem:
                        print(f"    - {elem['type']} (tag={elem['instance_tag']})")
                    else:
                        print(f"    - {elem['type']}")

            pos += info['frame_length']
            frame_num += 1

        # Count all frames
        print("\n" + "=" * 70)
        print("Full Stream Statistics")
        print("=" * 70)

        pos = 0
        total_frames = 0
        total_errors = 0

        while pos < len(data) - 7:
            info = parse_adts_header(data, pos)
            if info is None:
                pos += 1
                total_errors += 1
                continue

            total_frames += 1
            pos += info['frame_length']

        print(f"Total frames: {total_frames}")
        print(f"Sync errors: {total_errors}")

        # Calculate expected duration
        if total_frames > 0 and info:
            samples_per_frame = 1024  # Standard for AAC-LC
            total_samples = total_frames * samples_per_frame
            duration = total_samples / info['sample_rate']
            print(f"Expected duration: {duration:.2f}s ({duration/60:.2f} min)")


def analyze_asc(asc_hex: str):
    """Analyze AudioSpecificConfig."""

    print("\n" + "=" * 70)
    print("AudioSpecificConfig Analysis")
    print("=" * 70)

    asc = bytes.fromhex(asc_hex)
    bits = ''.join(format(b, '08b') for b in asc)

    print(f"Raw ASC: {asc.hex()}")
    print(f"Length: {len(asc)} bytes ({len(bits)} bits)")

    # audioObjectType (5 bits)
    aot = int(bits[0:5], 2)
    aot_names = {1: 'AAC Main', 2: 'AAC LC', 3: 'AAC SSR', 4: 'AAC LTP', 5: 'SBR'}
    print(f"\naudioObjectType: {aot} ({aot_names.get(aot, 'Unknown')})")

    # samplingFrequencyIndex (4 bits)
    sri = int(bits[5:9], 2)
    sr = SAMPLE_RATES[sri] if sri < len(SAMPLE_RATES) else 'explicit'
    print(f"samplingFrequencyIndex: {sri} ({sr} Hz)")

    # channelConfiguration (4 bits)
    cc = int(bits[9:13], 2)
    cc_names = {0: 'PCE', 1: 'Mono', 2: 'Stereo', 3: '3.0', 4: '4.0', 5: '5.0', 6: '5.1', 7: '7.1'}
    print(f"channelConfiguration: {cc} ({cc_names.get(cc, 'Unknown')})")

    if cc == 0:
        # GASpecificConfig follows for AOT 1,2,3,4
        print("\nGASpecificConfig:")
        print(f"  frameLengthFlag: {bits[13]}")
        print(f"  dependsOnCoreCoder: {bits[14]}")
        print(f"  extensionFlag: {bits[15]}")

        # PCE starts at bit 16
        pce_start = 16
        print(f"\nProgram Config Element (at bit {pce_start}):")

        eit = int(bits[pce_start:pce_start+4], 2)
        print(f"  element_instance_tag: {eit}")

        ot = int(bits[pce_start+4:pce_start+6], 2)
        print(f"  object_type: {ot}")

        pce_sri = int(bits[pce_start+6:pce_start+10], 2)
        pce_sr = SAMPLE_RATES[pce_sri] if pce_sri < len(SAMPLE_RATES) else 'unknown'
        match = "✓ MATCH" if pce_sri == sri else "✗ MISMATCH!"
        print(f"  sampling_frequency_index: {pce_sri} ({pce_sr} Hz) {match}")

        # Channel counts
        pos = pce_start + 10
        num_front = int(bits[pos:pos+4], 2)
        num_side = int(bits[pos+4:pos+8], 2)
        num_back = int(bits[pos+8:pos+12], 2)
        num_lfe = int(bits[pos+12:pos+14], 2)
        num_assoc = int(bits[pos+14:pos+17], 2)
        num_cc = int(bits[pos+17:pos+21], 2)

        print("\n  Channel Element Counts:")
        print(f"    num_front_channel_elements: {num_front}")
        print(f"    num_side_channel_elements: {num_side}")
        print(f"    num_back_channel_elements: {num_back}")
        print(f"    num_lfe_channel_elements: {num_lfe}")
        print(f"    num_assoc_data_elements: {num_assoc}")
        print(f"    num_valid_cc_elements: {num_cc}")

        # Check for text at end
        try:
            text_start = len(asc) - 20
            if text_start > 0:
                text = asc[text_start:].decode('latin1', errors='replace')
                if any(c.isalpha() for c in text):
                    print(f"\n  Embedded text (encoder info): {repr(text)}")
        except UnicodeDecodeError:
            pass


def main():
    """Entry point for ADTS/ASC analyzer."""
    if len(sys.argv) < 2:
        print("ADTS/AAC Analyzer for Engine DJ Stems")
        print("=" * 50)
        print("\nUsage:")
        print("  python analyze_adts.py <stems_file>")
        print("  python analyze_adts.py --asc <hex_string>")
        print("\nExamples:")
        print('  python analyze_adts.py "stems/1 xyz.stems"')
        print('  python analyze_adts.py --asc 1200050848002008c8200e4c61766335382e3133342e31303056e500')
        sys.exit(1)

    if sys.argv[1] == '--asc' and len(sys.argv) > 2:
        analyze_asc(sys.argv[2])
    else:
        analyze_stems_file(sys.argv[1])

        # Also analyze known ASC
        print("\n")
        analyze_asc('1200050848002008c8200e4c61766335382e3133342e31303056e500')


if __name__ == "__main__":
    main()
