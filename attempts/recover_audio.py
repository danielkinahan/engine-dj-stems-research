#!/usr/bin/env python3
"""
Recover as much audio as possible from Engine DJ stems files by
extracting successfully decoded chunks.

The decoder can decode ~14 frames before errors cascade. This script
tries to maximize recovery by using different approaches.
"""

import subprocess
import sys
import os
from pathlib import Path
import tempfile
import wave
import numpy as np


def extract_aac_frames(input_file):
    """Extract raw AAC frames from the MP4 container."""
    # Use ffmpeg to extract raw ADTS
    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as f:
        adts_path = f.name

    subprocess.run([
        'ffmpeg', '-y', '-v', 'error',
        '-i', str(input_file),
        '-c:a', 'copy',
        '-f', 'adts',
        adts_path
    ], check=True)

    return adts_path


def parse_adts_frames(adts_path):
    """Parse ADTS file into individual frames."""
    frames = []

    with open(adts_path, 'rb') as f:
        data = f.read()

    pos = 0
    while pos < len(data) - 7:
        # Look for sync word
        if data[pos] != 0xFF or (data[pos+1] & 0xF0) != 0xF0:
            pos += 1
            continue

        # Parse ADTS header
        header = data[pos:pos+7]

        protection_absent = (header[1] >> 0) & 1
        header_size = 7 if protection_absent else 9

        # Frame length (13 bits)
        frame_length = ((header[3] & 0x03) << 11) | (header[4] << 3) | ((header[5] >> 5) & 0x07)

        if frame_length < header_size or pos + frame_length > len(data):
            pos += 1
            continue

        frame_data = data[pos:pos+frame_length]
        frames.append({
            'offset': pos,
            'length': frame_length,
            'data': frame_data
        })

        pos += frame_length

    return frames


def decode_frame_chunk(frames, start_idx, count, sample_rate=44100, channels=8):
    """Try to decode a chunk of frames starting at start_idx."""

    # Write frames to temp ADTS file
    with tempfile.NamedTemporaryFile(suffix='.aac', delete=False) as f:
        temp_aac = f.name
        for i in range(start_idx, min(start_idx + count, len(frames))):
            f.write(frames[i]['data'])

    # Try to decode
    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
        temp_wav = f.name

    result = subprocess.run([
        'ffmpeg', '-y', '-v', 'error',
        '-i', temp_aac,
        '-c:a', 'pcm_s16le',
        temp_wav
    ], capture_output=True)

    decoded_samples = None
    if os.path.exists(temp_wav) and os.path.getsize(temp_wav) > 100:
        try:
            with wave.open(temp_wav, 'rb') as wf:
                n_channels = wf.getnchannels()
                n_frames = wf.getnframes()
                if n_frames > 0 and n_channels == channels:
                    raw_data = wf.readframes(n_frames)
                    decoded_samples = np.frombuffer(raw_data, dtype=np.int16)
                    decoded_samples = decoded_samples.reshape(-1, n_channels)
        except:
            pass

    # Cleanup
    if os.path.exists(temp_aac):
        os.unlink(temp_aac)
    if os.path.exists(temp_wav):
        os.unlink(temp_wav)

    return decoded_samples


def recover_audio_chunked(input_file, output_dir, chunk_size=10):
    """Try to recover audio by decoding in chunks."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    print(f"Extracting AAC frames from {input_file}...")
    adts_path = extract_aac_frames(input_file)

    print("Parsing ADTS frames...")
    frames = parse_adts_frames(adts_path)
    print(f"Found {len(frames)} frames")

    # Calculate expected duration
    samples_per_frame = 1024
    expected_duration = len(frames) * samples_per_frame / 44100
    print(f"Expected duration: {expected_duration:.1f} seconds")

    # Try decoding from the beginning
    print(f"\nTrying to decode first {chunk_size} frames...")
    samples = decode_frame_chunk(frames, 0, chunk_size)

    if samples is not None:
        print(f"Successfully decoded {len(samples)} samples ({len(samples)/44100:.2f}s)")
        print(f"Shape: {samples.shape}")

        # Save the successfully decoded portion
        output_file = output_dir / "recovered_start.wav"
        with wave.open(str(output_file), 'wb') as wf:
            wf.setnchannels(8)
            wf.setsampwidth(2)
            wf.setframerate(44100)
            wf.writeframes(samples.tobytes())
        print(f"Saved: {output_file}")

        # Split into stems
        stem_names = ['drums', 'bass', 'melody', 'vocals']
        for i, name in enumerate(stem_names):
            left = samples[:, i*2]
            right = samples[:, i*2+1]
            stereo = np.stack([left, right], axis=1)

            stem_file = output_dir / f"recovered_{name}.wav"
            with wave.open(str(stem_file), 'wb') as wf:
                wf.setnchannels(2)
                wf.setsampwidth(2)
                wf.setframerate(44100)
                wf.writeframes(stereo.tobytes())
            print(f"  Stem: {stem_file}")
    else:
        print("Could not decode any frames")

    # Try decoding from different offsets
    print("\n\nTrying to decode from different offsets...")

    recovered_chunks = []
    for start in range(0, min(100, len(frames)), chunk_size):
        samples = decode_frame_chunk(frames, start, chunk_size)
        if samples is not None and len(samples) > 1000:
            recovered_chunks.append({
                'start_frame': start,
                'samples': samples
            })
            print(f"  Offset {start}: decoded {len(samples)} samples")

    print(f"\nRecovered {len(recovered_chunks)} chunks")

    # Cleanup
    os.unlink(adts_path)

    return recovered_chunks


def main():
    if len(sys.argv) < 2:
        stems_dir = Path("stems")
        if stems_dir.exists():
            stems = list(stems_dir.glob("*.stems"))
            if stems:
                input_file = str(stems[0])
            else:
                print("No .stems files found")
                sys.exit(1)
        else:
            print("Usage: python recover_audio.py <input.stems>")
            sys.exit(1)
    else:
        input_file = sys.argv[1]

    output_dir = Path("recovered_output")
    recover_audio_chunked(input_file, output_dir)


if __name__ == '__main__':
    main()
