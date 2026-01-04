#!/usr/bin/env python3
"""
Decode Engine DJ stem files using fdkaac.

Engine DJ stems are MP4 containers with 8-channel AAC audio where
the channel configuration is defined via a Program Config Element (PCE).
Standard ffmpeg AAC decoder has issues with this configuration,
but fdkaac may handle it better.

This script attempts multiple decoding strategies.
"""

import subprocess
import argparse
import sys
import json
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple


@dataclass
class AudioInfo:
    """Container for audio stream information"""
    format_name: str
    duration: float
    bit_rate: int
    codec_name: str
    channels: int
    sample_rate: int
    stream_bit_rate: int


def check_tools() -> dict:
    """Check which tools are available"""
    tools = {
        'ffmpeg': shutil.which('ffmpeg'),
        'ffprobe': shutil.which('ffprobe'),
        'fdkaac': shutil.which('fdkaac'),
        'faad': shutil.which('faad'),
    }
    return {k: v is not None for k, v in tools.items()}


def get_audio_info(input_file: Path) -> Optional[AudioInfo]:
    """Get audio stream information using ffprobe"""
    cmd = [
        'ffprobe', '-v', 'error',
        '-show_entries', 'format=format_name,duration,bit_rate:stream=codec_name,channels,sample_rate,bit_rate',
        '-of', 'json',
        str(input_file)
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)

        fmt = data.get('format', {})
        streams = data.get('streams', [{}])
        stream = streams[0] if streams else {}

        return AudioInfo(
            format_name=fmt.get('format_name', 'unknown'),
            duration=float(fmt.get('duration', 0)),
            bit_rate=int(fmt.get('bit_rate', 0)),
            codec_name=stream.get('codec_name', 'unknown'),
            channels=int(stream.get('channels', 0)),
            sample_rate=int(stream.get('sample_rate', 0)),
            stream_bit_rate=int(stream.get('bit_rate', 0))
        )
    except Exception as e:
        print(f"Error getting audio info: {e}")
        return None


def extract_raw_aac(input_file: Path, output_file: Path) -> bool:
    """Extract raw AAC stream from MP4 container"""
    cmd = [
        'ffmpeg', '-hide_banner', '-y',
        '-i', str(input_file),
        '-vn', '-acodec', 'copy',
        str(output_file)
    ]

    subprocess.run(cmd, capture_output=True, text=True, check=False)
    return output_file.exists() and output_file.stat().st_size > 0


def decode_with_fdkaac(input_file: Path, output_file: Path) -> Tuple[bool, str]:
    """
    Try to decode AAC using fdkaac.
    Note: fdkaac is primarily an encoder, so this might not work directly.
    """
    # fdkaac is an encoder, not decoder. Check if it has decode capability
    result = subprocess.run(['fdkaac', '--help'], capture_output=True, text=True, check=False)
    help_text = result.stdout + result.stderr

    if 'decode' in help_text.lower():
        cmd = ['fdkaac', '-d', str(input_file), '-o', str(output_file)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        success = output_file.exists() and output_file.stat().st_size > 1000
        return success, result.stderr
    return False, "fdkaac does not support decoding"


def decode_with_faad(input_file: Path, output_file: Path) -> Tuple[bool, str]:
    """Try to decode AAC using faad"""
    cmd = ['faad', '-o', str(output_file), str(input_file)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    success = output_file.exists() and output_file.stat().st_size > 1000
    return success, result.stderr


def decode_with_ffmpeg_fdk(input_file: Path, output_file: Path) -> Tuple[bool, str]:
    """Try to decode using ffmpeg with libfdk_aac decoder if available"""
    # Check if libfdk_aac decoder is available
    result = subprocess.run(
        ['ffmpeg', '-decoders'],
        capture_output=True, text=True, check=False
    )

    if 'libfdk_aac' not in result.stdout:
        return False, "libfdk_aac decoder not available in ffmpeg"

    cmd = [
        'ffmpeg', '-hide_banner', '-y',
        '-c:a', 'libfdk_aac',
        '-i', str(input_file),
        '-acodec', 'pcm_s16le',
        str(output_file)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    success = output_file.exists() and output_file.stat().st_size > 1000
    return success, result.stderr


def decode_with_ffmpeg_native(input_file: Path, output_file: Path) -> Tuple[bool, str]:
    """Try to decode using ffmpeg native AAC decoder with error tolerance"""
    cmd = [
        'ffmpeg', '-hide_banner', '-y',
        '-err_detect', 'ignore_err',
        '-i', str(input_file),
        '-vn',
        '-acodec', 'pcm_s16le',
        '-ar', '44100',
        str(output_file)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    success = output_file.exists() and output_file.stat().st_size > 1000
    return success, result.stderr


def split_channels(input_file: Path, output_dir: Path, stem_names: List[str]) -> List[Path]:
    """Split 8-channel audio into 4 stereo files"""
    output_files = []
    base_name = input_file.stem

    # Build filter to split channels
    filter_complex = (
        "[0:a]pan=stereo|c0=c0|c1=c1[s1];"
        "[0:a]pan=stereo|c0=c2|c1=c3[s2];"
        "[0:a]pan=stereo|c0=c4|c1=c5[s3];"
        "[0:a]pan=stereo|c0=c6|c1=c7[s4]"
    )

    cmd = [
        'ffmpeg', '-hide_banner', '-y',
        '-i', str(input_file),
        '-filter_complex', filter_complex,
    ]

    for i, stem_name in enumerate(stem_names, 1):
        output_file = output_dir / f"{base_name}_{stem_name}.wav"
        cmd.extend(['-map', f'[s{i}]', '-acodec', 'pcm_s16le', str(output_file)])
        output_files.append(output_file)

    subprocess.run(cmd, capture_output=True, check=False)
    return output_files


def process_stem_file(input_file: Path, output_dir: Path) -> bool:
    """Process a single stem file"""
    print(f"\n{'='*60}")
    print(f"Processing: {input_file.name}")
    print(f"{'='*60}")

    # Get audio info
    info = get_audio_info(input_file)
    if info:
        print("\nAudio Info:")
        print(f"  Format: {info.format_name}")
        print(f"  Duration: {info.duration:.2f}s ({info.duration/60:.2f} min)")
        print(f"  Codec: {info.codec_name}")
        print(f"  Channels: {info.channels}")
        print(f"  Sample Rate: {info.sample_rate} Hz")
        print(f"  Bitrate: {info.bit_rate // 1000} kbps")

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = input_file.stem

    # Step 1: Extract raw AAC
    print("\nStep 1: Extracting raw AAC stream...")
    raw_aac = output_dir / f"{base_name}_raw.aac"
    if not extract_raw_aac(input_file, raw_aac):
        print("  ✗ Failed to extract AAC stream")
        return False
    print(f"  ✓ Extracted: {raw_aac.stat().st_size / 1024 / 1024:.2f} MB")

    # Step 2: Try various decoders
    print("\nStep 2: Attempting to decode AAC...")
    decoded_wav = output_dir / f"{base_name}_decoded.wav"

    decoders = [
        ("ffmpeg with libfdk_aac", lambda: decode_with_ffmpeg_fdk(raw_aac, decoded_wav)),
        ("fdkaac", lambda: decode_with_fdkaac(raw_aac, decoded_wav)),
        ("faad", lambda: decode_with_faad(raw_aac, decoded_wav)),
        ("ffmpeg native (with error tolerance)", lambda: decode_with_ffmpeg_native(input_file, decoded_wav)),
    ]

    decoded = False
    for decoder_name, decode_func in decoders:
        print(f"\n  Trying {decoder_name}...")
        try:
            success, message = decode_func()
            if success:
                size_mb = decoded_wav.stat().st_size / 1024 / 1024
                expected_size = (info.duration * info.sample_rate * info.channels * 2) / (1024 * 1024) if info else 0

                print(f"    ✓ Decoded: {size_mb:.2f} MB")

                # Check if the file is reasonably sized
                if expected_size > 0:
                    ratio = size_mb / expected_size
                    print(f"    Expected size: ~{expected_size:.2f} MB (ratio: {ratio:.1%})")

                    if ratio < 0.5:
                        print("    ⚠ Output seems too small, decoding may have failed")
                        continue

                decoded = True
                break
            if not success:
                print(f"    ✗ Failed: {message[:100]}...")
                continue
        except Exception as e:
            print(f"    ✗ Error: {e}")

    if not decoded:
        print("\n✗ All decoders failed!")
        # Clean up
        if raw_aac.exists():
            raw_aac.unlink()
        return False

    # Step 3: Split channels
    print("\nStep 3: Splitting into individual stems...")
    stem_names = ['drums', 'bass', 'melody', 'vocals']
    output_files = split_channels(decoded_wav, output_dir, stem_names)

    print("\nResults:")
    all_success = True
    for _, (stem_name, output_file) in enumerate(zip(stem_names, output_files)):
        if output_file.exists() and output_file.stat().st_size > 1000:
            size_mb = output_file.stat().st_size / 1024 / 1024
            print(f"  ✓ {stem_name}: {output_file.name} ({size_mb:.2f} MB)")
        else:
            print(f"  ✗ {stem_name}: Failed")
            all_success = False

    # Clean up intermediate files
    if raw_aac.exists():
        raw_aac.unlink()
    if decoded_wav.exists():
        decoded_wav.unlink()

    return all_success


def main():
    """CLI entry to decode .stems files and split into WAV stems."""

    parser = argparse.ArgumentParser(
        description='Decode Engine DJ .stems files to individual WAV stems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool attempts to decode Engine DJ stem files using multiple
AAC decoders (fdkaac, faad, ffmpeg) to find one that works with
the unusual 8-channel PCE configuration used by Engine DJ.

The stem files contain 4 stereo tracks (8 channels total):
  - Drums (channels 0-1)
  - Bass (channels 2-3)
  - Melody (channels 4-5)
  - Vocals (channels 6-7)
        """
    )

    parser.add_argument('input', nargs='*', help='Input .stems file(s)')
    parser.add_argument('-o', '--output', default='output',
                        help='Output directory (default: output)')
    parser.add_argument('--check-tools', action='store_true',
                        help='Check available decoding tools')

    args = parser.parse_args()

    if args.check_tools:
        print("Checking available tools:")
        tools = check_tools()
        for tool, available in tools.items():
            status = "✓ Available" if available else "✗ Not found"
            print(f"  {tool}: {status}")
        return

    if not args.input:
        # Default: process all .stems files in stems/
        stems_dir = Path(__file__).parent / 'stems'
        if stems_dir.exists():
            args.input = list(stems_dir.glob('*.stems'))

        if not args.input:
            parser.print_help()
            return

    output_dir = Path(args.output)

    # Check tools
    tools = check_tools()
    print("Available tools:")
    for tool, available in tools.items():
        status = "✓" if available else "✗"
        print(f"  {status} {tool}")

    if not tools['ffmpeg']:
        print("\nError: ffmpeg is required!")
        sys.exit(1)

    # Process files
    success_count = 0
    for input_path in args.input:
        input_file = Path(input_path) if isinstance(input_path, str) else input_path
        if process_stem_file(input_file, output_dir):
            success_count += 1

    print(f"\n{'='*60}")
    print(f"Completed: {success_count}/{len(args.input)} files processed successfully")


if __name__ == '__main__':
    main()
