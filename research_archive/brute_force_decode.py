#!/usr/bin/env python3
"""
Aggressive approach: Re-encode by remuxing with explicit channel mapping.

Since I can't decode the AAC directly, i'll try a different approach:
1. Try to force ffmpeg to treat it as 8 separate mono channels
2. Use experimental decoder options
3. Try error-resilient mode
"""

import subprocess
import sys
import os
from pathlib import Path


def try_decode_with_options(input_file, output_file, options, description):
    """Try decoding with specific ffmpeg options."""
    print(f"\n=== Trying: {description} ===")

    cmd = ['ffmpeg', '-y', '-v', 'warning'] + options + [
        '-i', str(input_file),
        '-c:a', 'pcm_s16le',
        str(output_file)
    ]

    print(f"Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode == 0 and os.path.exists(output_file) and os.path.getsize(output_file) > 1000:
        print(f"SUCCESS! Output: {output_file} ({os.path.getsize(output_file)} bytes)")
        return True

    print(f"Failed: {result.stderr[:500] if result.stderr else 'Unknown error'}")
    return False


def try_extract_raw_pcm(input_file, output_dir):
    """Try various extraction approaches."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    # Approach 1: Use aac decoder with strict=-2 (very strict)
    try_decode_with_options(
        input_file,
        output_dir / "approach1_strict.wav",
        ['-strict', '-2'],
        "Strict mode -2"
    )

    # Approach 2: Use aac_fixed decoder
    try_decode_with_options(
        input_file,
        output_dir / "approach2_aac_fixed.wav",
        ['-c:a', 'aac_fixed'],
        "AAC fixed-point decoder"
    )

    # Approach 3: Ignore errors with -err_detect ignore_err
    try_decode_with_options(
        input_file,
        output_dir / "approach3_ignore_err.wav",
        ['-err_detect', 'ignore_err'],
        "Ignore errors"
    )

    # Approach 4: Request_channel_layout to force interpretation
    try_decode_with_options(
        input_file,
        output_dir / "approach4_channel_layout.wav",
        ['-request_channel_layout', '7.1'],
        "Request 7.1 channel layout"
    )

    # Approach 5: Map individual channels with amerge
    # First extract to raw format, then recombine

    # Approach 6: Use lavfi to force channel count
    try_decode_with_options(
        input_file,
        output_dir / "approach6_lavfi.wav",
        ['-channel_layout', '7.1'],
        "Force channel layout via -channel_layout"
    )

    # Approach 7: Use af channelmap
    try_decode_with_options(
        input_file,
        output_dir / "approach7_channelmap.wav",
        ['-af', 'channelmap=channel_layout=7.1'],
        "Use channelmap filter"
    )

    # Approach 8: Copy raw audio frames to a new container
    print("\n=== Trying: Raw copy to MKV container ===")
    mkv_file = output_dir / "raw_copy.mkv"
    result = subprocess.run([
        'ffmpeg', '-y', '-v', 'warning',
        '-i', str(input_file),
        '-c:a', 'copy',
        str(mkv_file)
    ], capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print(f"Created: {mkv_file}")
        # Now try to decode from MKV
        try_decode_with_options(
            mkv_file,
            output_dir / "approach8_from_mkv.wav",
            [],
            "Decode from MKV container"
        )

    # Approach 9: Extract raw AAC to ADTS and try to decode
    print("\n=== Trying: Extract to ADTS ===")
    adts_file = output_dir / "raw.aac"
    result = subprocess.run([
        'ffmpeg', '-y', '-v', 'warning',
        '-i', str(input_file),
        '-c:a', 'copy',
        '-f', 'adts',
        str(adts_file)
    ], capture_output=True, text=True, check=False)

    if result.returncode == 0:
        print(f"Created: {adts_file}")
        # Try to decode ADTS
        try_decode_with_options(
            adts_file,
            output_dir / "approach9_from_adts.wav",
            [],
            "Decode from raw ADTS"
        )

        # Try with fdk decoder if available
        try_decode_with_options(
            adts_file,
            output_dir / "approach9b_fdk.wav",
            ['-c:a', 'libfdk_aac'],
            "Decode ADTS with libfdk_aac"
        )

    # Approach 10: Try using SoX
    print("\n=== Trying: SoX playback ===")
    result = subprocess.run(['which', 'sox'], capture_output=True, check=False)
    if result.returncode == 0:
        sox_out = output_dir / "approach10_sox.wav"
        result = subprocess.run([
            'sox', str(input_file), str(sox_out)
        ], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            print(f"SoX succeeded: {sox_out}")
        else:
            print(f"SoX failed: {result.stderr[:300]}")

    # Approach 11: Try VLC command line
    print("\n=== Trying: VLC transcode ===")
    result = subprocess.run(['which', 'cvlc'], capture_output=True, check=False)
    if result.returncode == 0:
        vlc_out = output_dir / "approach11_vlc.wav"
        result = subprocess.run([
            'cvlc', str(input_file),
            '--sout', f'#transcode{{acodec=s16l,channels=8}}:std{{access=file,mux=wav,dst={vlc_out}}}',
            'vlc://quit'
        ], capture_output=True, text=True, timeout=60, check=False)
        if result.returncode == 0 and os.path.exists(vlc_out):
            print(f"VLC succeeded: {vlc_out}")
        else:
            print(f"VLC failed: {result.stderr[:300] if result.stderr else 'Unknown'}")

    # Approach 12: Try mplayer/mpv
    print("\n=== Trying: MPV extraction ===")
    result = subprocess.run(['which', 'mpv'], capture_output=True, check=False)
    if result.returncode == 0:
        mpv_out = output_dir / "approach12_mpv.wav"
        result = subprocess.run([
            'mpv', str(input_file),
            '-ao', f'pcm:file={mpv_out}',
            '--no-video'
        ], capture_output=True, text=True, timeout=120, check=False)
        if os.path.exists(mpv_out) and os.path.getsize(mpv_out) > 1000:
            print(f"MPV succeeded: {mpv_out}")
        else:
            print("MPV failed")


def main():
    """Entry point to run brute-force decode attempts against a stems file."""
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
            print("Usage: python brute_force_decode.py <input.stems>")
            sys.exit(1)
    else:
        input_file = sys.argv[1]

    output_dir = Path("brute_force_output")
    try_extract_raw_pcm(input_file, output_dir)

    print("\n" + "="*60)
    print("Summary of outputs:")
    print("="*60)

    for f in sorted(output_dir.glob("*.wav")):
        size = os.path.getsize(f)
        if size > 1000:
            # Check if it has actual audio content
            result = subprocess.run([
                'ffprobe', '-v', 'error', '-show_entries',
                'stream=channels,sample_rate,duration',
                '-of', 'csv=p=0', str(f)
            ], capture_output=True, text=True, check=False)
            print(f"✓ {f.name}: {size/1024:.1f}KB - {result.stdout.strip()}")
        else:
            print(f"✗ {f.name}: {size} bytes (too small)")


if __name__ == '__main__':
    main()
