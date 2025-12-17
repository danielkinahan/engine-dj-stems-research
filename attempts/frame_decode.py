#!/usr/bin/env python3
"""
Attempt to decode Engine DJ stems by processing frames individually
and understanding the decoder state issues.
"""

import subprocess
import sys
import os
import tempfile
from pathlib import Path


def extract_adts_frames(stems_path: str) -> list:
    """Extract ADTS stream and parse into frames."""

    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as tmp:
        adts_path = tmp.name

    # Extract ADTS
    cmd = ['ffmpeg', '-y', '-i', stems_path, '-c:a', 'copy', '-vn', adts_path]
    subprocess.run(cmd, capture_output=True)

    with open(adts_path, 'rb') as f:
        data = f.read()

    os.unlink(adts_path)

    # Parse frames
    frames = []
    pos = 0

    while pos < len(data) - 7:
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue

        h = data[pos:pos+7]
        protection_absent = h[1] & 1
        frame_len = ((h[3] & 3) << 11) | (h[4] << 3) | ((h[5] >> 5) & 7)

        if frame_len > 0 and pos + frame_len <= len(data):
            frames.append(data[pos:pos+frame_len])
            pos += frame_len
        else:
            pos += 1

    return frames


def try_decode_n_frames(frames: list, n: int, output_path: str) -> bool:
    """Try to decode first n frames."""

    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as tmp:
        tmp.write(b''.join(frames[:n]))
        tmp_aac = tmp.name

    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tmp:
        tmp_wav = tmp.name

    cmd = [
        'ffmpeg', '-y',
        '-i', tmp_aac,
        '-c:a', 'pcm_s16le',
        tmp_wav
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    os.unlink(tmp_aac)

    success = False
    if os.path.exists(tmp_wav):
        size = os.path.getsize(tmp_wav)
        if size > 1000:
            # Check channel count
            probe = subprocess.run(
                ['ffprobe', '-v', 'error', '-select_streams', 'a:0',
                 '-show_entries', 'stream=channels', '-of', 'csv=p=0', tmp_wav],
                capture_output=True, text=True
            )
            channels = int(probe.stdout.strip()) if probe.stdout.strip() else 0
            print(f"  {n} frames -> {size} bytes, {channels} channels")

            if channels == 8:
                # This worked! Save it
                os.rename(tmp_wav, output_path)
                success = True
            else:
                os.unlink(tmp_wav)
        else:
            os.unlink(tmp_wav)

    return success


def decode_frame_by_frame(stems_path: str, output_dir: str):
    """Try different strategies to decode the stems."""

    print(f"Processing: {stems_path}")
    print("=" * 60)

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print("\nExtracting frames...")
    frames = extract_adts_frames(stems_path)
    print(f"Found {len(frames)} ADTS frames")

    # Try decoding increasing numbers of frames
    print("\nTrying to decode frames...")
    for n in [1, 2, 5, 10, 50, 100, 500, 1000, len(frames)]:
        if n > len(frames):
            n = len(frames)

        output = os.path.join(output_dir, f'test_{n}_frames.wav')
        if try_decode_n_frames(frames, n, output):
            print(f"  SUCCESS with {n} frames!")
            break


def main():
    if len(sys.argv) < 2:
        print("Usage: python frame_decode.py <stems_file> [output_dir]")
        sys.exit(1)

    stems_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'output'

    decode_frame_by_frame(stems_path, output_dir)


if __name__ == "__main__":
    main()
