#!/usr/bin/env python3
"""
Decode Engine DJ .stems files using PyAV (libav/ffmpeg bindings).
PyAV may handle the PCE-based channel configuration differently.
"""

import sys
import os
from pathlib import Path

import av
import numpy as np
import soundfile as sf


def decode_stems(input_path: str, output_dir: str = None):
    """Decode a .stems file and split into individual stem WAV files."""

    input_path = Path(input_path)
    if output_dir is None:
        output_dir = input_path.parent / input_path.stem
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    stem_names = ['drums', 'bass', 'melody', 'vocals']

    print(f"Opening: {input_path}")

    try:
        container = av.open(str(input_path))
    except Exception as e:
        print(f"Failed to open file: {e}")
        return False

    # Get audio stream info
    audio_stream = container.streams.audio[0]
    print(f"Codec: {audio_stream.codec_context.name}")
    print(f"Channels: {audio_stream.channels}")
    print(f"Sample rate: {audio_stream.sample_rate}")
    print(f"Duration: {float(audio_stream.duration * audio_stream.time_base):.2f}s")

    if audio_stream.channels != 8:
        print(f"Warning: Expected 8 channels, got {audio_stream.channels}")

    # Collect all audio samples
    print("\nDecoding audio...")
    all_samples = []
    frame_count = 0
    error_count = 0

    for packet in container.demux(audio_stream):
        try:
            for frame in packet.decode():
                # Convert to numpy array
                # frame.to_ndarray() returns shape (channels, samples) for planar formats
                # or (samples, channels) for interleaved
                arr = frame.to_ndarray()

                # Ensure we have (samples, channels) format
                if arr.shape[0] == audio_stream.channels:
                    arr = arr.T

                all_samples.append(arr)
                frame_count += 1

                if frame_count % 1000 == 0:
                    print(f"  Decoded {frame_count} frames...")

        except Exception as e:
            error_count += 1
            if error_count <= 5:
                print(f"  Decode error: {e}")
            elif error_count == 6:
                print("  (suppressing further errors...)")
            continue

    container.close()

    if not all_samples:
        print("No samples decoded!")
        return False

    print(f"\nDecoded {frame_count} frames ({error_count} errors)")

    # Concatenate all samples
    audio_data = np.concatenate(all_samples, axis=0)
    print(f"Total samples: {audio_data.shape[0]}, Channels: {audio_data.shape[1]}")

    # Normalize to float32 range [-1, 1] if needed
    if audio_data.dtype in [np.int16, np.int32]:
        max_val = np.iinfo(audio_data.dtype).max
        audio_data = audio_data.astype(np.float32) / max_val
    elif audio_data.dtype != np.float32:
        audio_data = audio_data.astype(np.float32)

    sample_rate = audio_stream.sample_rate

    # Split into 4 stereo pairs
    # Assuming channel layout: [drums_L, drums_R, bass_L, bass_R, melody_L, melody_R, vocals_L, vocals_R]
    print(f"\nSplitting into {len(stem_names)} stems...")

    for i, name in enumerate(stem_names):
        left_ch = i * 2
        right_ch = i * 2 + 1

        if right_ch < audio_data.shape[1]:
            stem_data = audio_data[:, left_ch:right_ch+1]
            output_path = output_dir / f"{name}.wav"

            sf.write(str(output_path), stem_data, sample_rate, subtype='PCM_16')

            duration = len(stem_data) / sample_rate
            print(f"  ✓ {name}.wav ({duration:.2f}s, {os.path.getsize(output_path) / 1024 / 1024:.2f} MB)")
        else:
            print(f"  ✗ {name}: Not enough channels")

    print(f"\nOutput directory: {output_dir}")
    return True


def main():
    """CLI entry to decode a .stems file via PyAV."""
    if len(sys.argv) < 2:
        print("Usage: python decode_pyav.py <stems_file> [output_dir]")
        print("\nExample:")
        print('  python decode_pyav.py "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems" ./output/')
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    success = decode_stems(input_file, output_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
