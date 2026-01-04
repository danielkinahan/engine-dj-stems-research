#!/usr/bin/env python3
"""
Fix Engine DJ .stems AAC by modifying ADTS headers to use standard channel config.

The ADTS header channel_configuration is set to 0 (PCE in stream), but most decoders
don't handle the PCE correctly. Let's try setting it to 7 (8 channels / 7.1).
"""

import sys
import os
import subprocess
import tempfile
from pathlib import Path


def parse_adts_header(data: bytes, offset: int) -> dict:
    """Parse an ADTS header at the given offset."""
    if len(data) < offset + 7:
        return None

    # ADTS header is 7 bytes (without CRC) or 9 bytes (with CRC)
    header = data[offset:offset+7]

    # Check sync word (12 bits)
    if header[0] != 0xFF or (header[1] & 0xF0) != 0xF0:
        return None

    # Parse header fields
    mpeg_version = (header[1] >> 3) & 0x01  # 0=MPEG-4, 1=MPEG-2
    layer = (header[1] >> 1) & 0x03  # always 0
    protection_absent = header[1] & 0x01  # 1=no CRC

    profile = (header[2] >> 6) & 0x03  # 0=Main, 1=LC, 2=SSR, 3=reserved
    sample_rate_index = (header[2] >> 2) & 0x0F
    private_bit = (header[2] >> 1) & 0x01
    channel_config = ((header[2] & 0x01) << 2) | ((header[3] >> 6) & 0x03)

    original_copy = (header[3] >> 5) & 0x01
    home = (header[3] >> 4) & 0x01

    # Frame length (13 bits)
    frame_length = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)

    # Buffer fullness (11 bits)
    buffer_fullness = ((header[5] & 0x1F) << 6) | ((header[6] >> 2) & 0x3F)

    # Number of AAC frames - 1
    num_frames = header[6] & 0x03

    header_size = 7 if protection_absent else 9

    return {
        'mpeg_version': mpeg_version,
        'profile': profile,
        'sample_rate_index': sample_rate_index,
        'channel_config': channel_config,
        'frame_length': frame_length,
        'buffer_fullness': buffer_fullness,
        'num_frames': num_frames,
        'protection_absent': protection_absent,
        'header_size': header_size,
    }


def write_adts_header(info: dict, new_channel_config: int = None) -> bytes:
    """Write an ADTS header with optionally modified channel config."""
    if new_channel_config is None:
        new_channel_config = info['channel_config']

    header = bytearray(7)

    # Sync word
    header[0] = 0xFF
    header[1] = 0xF0 | (info['mpeg_version'] << 3) | (0 << 1) | info['protection_absent']

    # Byte 2
    header[2] = (info['profile'] << 6) | (info['sample_rate_index'] << 2) | ((new_channel_config >> 2) & 0x01)

    # Byte 3
    header[3] = ((new_channel_config & 0x03) << 6) | (info['frame_length'] >> 11)

    # Byte 4
    header[4] = (info['frame_length'] >> 3) & 0xFF

    # Byte 5
    header[5] = ((info['frame_length'] & 0x07) << 5) | (info['buffer_fullness'] >> 6)

    # Byte 6
    header[6] = ((info['buffer_fullness'] & 0x3F) << 2) | info['num_frames']

    return bytes(header)


def fix_adts_stream(input_path: str, output_path: str, new_channel_config: int = 7) -> bool:
    """Fix an ADTS stream by modifying channel configuration in all headers."""

    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    print(f"Input size: {len(data):,} bytes")

    # Find and fix all ADTS headers
    pos = 0
    frame_count = 0
    modified_count = 0

    while pos < len(data) - 7:
        # Look for sync word
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue

        info = parse_adts_header(data, pos)
        if info is None:
            pos += 1
            continue

        frame_count += 1

        if info['channel_config'] != new_channel_config:
            # Write new header
            new_header = write_adts_header(info, new_channel_config)
            data[pos:pos+7] = new_header
            modified_count += 1

        if frame_count <= 3:
            print(f"  Frame {frame_count}: offset={pos}, len={info['frame_length']}, ch={info['channel_config']}")

        # Move to next frame
        pos += info['frame_length']

    print(f"Found {frame_count} frames, modified {modified_count} headers")

    with open(output_path, 'wb') as f:
        f.write(data)

    return True


def extract_and_fix(stems_path: str, output_dir: str) -> bool:
    """Extract AAC from stems, fix headers, decode, and split."""

    stem_names = ['drums', 'bass', 'melody', 'vocals']

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        raw_aac = os.path.join(tmpdir, 'raw.aac')
        fixed_aac = os.path.join(tmpdir, 'fixed.aac')
        full_wav = os.path.join(tmpdir, 'full_8ch.wav')

        # Extract raw AAC
        print("Step 1: Extracting raw AAC from stems...")
        cmd = ['ffmpeg', '-y', '-i', stems_path, '-c:a', 'copy', '-vn', raw_aac]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"Extraction failed: {result.stderr[-500:]}")
            return False
        print(f"  Extracted: {os.path.getsize(raw_aac) / 1024 / 1024:.2f} MB")

        # Fix ADTS headers
        print("\nStep 2: Fixing ADTS headers...")
        fix_adts_stream(raw_aac, fixed_aac, new_channel_config=7)

        # Decode fixed AAC
        print("\nStep 3: Decoding fixed AAC...")
        cmd = [
            'ffmpeg', '-y',
            '-i', fixed_aac,
            '-c:a', 'pcm_s16le',
            full_wav
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            print(f"Decode failed: {result.stderr[-500:]}")
            return False

        if not os.path.exists(full_wav) or os.path.getsize(full_wav) < 1000000:
            print("Output too small, trying with error tolerance...")
            cmd = [
                'ffmpeg', '-y',
                '-err_detect', 'ignore_err',
                '-i', fixed_aac,
                '-c:a', 'pcm_s16le',
                full_wav
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        wav_size = os.path.getsize(full_wav) if os.path.exists(full_wav) else 0
        print(f"  Decoded: {wav_size / 1024 / 1024:.2f} MB")

        if wav_size < 1000000:
            print("Decoding still failed")
            return False

        # Get channel count from decoded file
        probe_cmd = ['ffprobe', '-v', 'error', '-select_streams', 'a:0',
                     '-show_entries', 'stream=channels', '-of', 'csv=p=0', full_wav]
        result = subprocess.run(probe_cmd, capture_output=True, text=True, check=False)
        channels = int(result.stdout.strip()) if result.stdout.strip() else 0
        print(f"  Channels in decoded file: {channels}")

        # Split into stems
        print("\nStep 4: Splitting into stems...")
        for i, name in enumerate(stem_names):
            left = i * 2
            right = i * 2 + 1

            if right >= channels:
                print(f"  ✗ {name}: Not enough channels (need ch {left} and {right}, have {channels})")
                continue

            output_path = os.path.join(output_dir, f'{name}.wav')

            cmd = [
                'ffmpeg', '-y',
                '-i', full_wav,
                '-af', f'pan=stereo|c0=c{left}|c1=c{right}',
                output_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode == 0 and os.path.exists(output_path):
                print(f"  ✓ {name}.wav ({os.path.getsize(output_path) / 1024 / 1024:.2f} MB)")
            else:
                print(f"  ✗ {name}: {result.stderr[-200:]}")

    print(f"\nOutput: {output_dir}")
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_adts.py <stems_file> [output_dir]")
        sys.exit(1)

    stems_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(stems_path).parent / Path(stems_path).stem)

    success = extract_and_fix(stems_path, output_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
