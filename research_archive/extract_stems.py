#!/usr/bin/env python3
"""
Extract individual stem tracks from Engine DJ .stems files.

Engine DJ stems are MP4 containers with 8-channel AAC audio.
The 8 channels contain 4 stereo stem pairs:
- Channels 0-1: Stem 1 (likely Drums)
- Channels 2-3: Stem 2 (likely Bass)
- Channels 4-5: Stem 3 (likely Melody/Synths)
- Channels 6-7: Stem 4 (likely Vocals)

The channel mapping in Engine DJ stems uses a Program Config Element (PCE)
with an unusual configuration that causes ffmpeg decoding issues.
"""

import subprocess
import sys
from pathlib import Path
import argparse
import shutil
import json


# Stem names based on typical Engine DJ stem separation
STEM_NAMES = ['drums', 'bass', 'melody', 'vocals']


def check_dependencies():
    """Check if required tools are available"""
    tools = ['ffmpeg', 'ffprobe']
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}")
        print("Please install ffmpeg to use this script.")
        sys.exit(1)


def get_audio_info(input_file):
    """Get audio stream information using ffprobe"""
    cmd = [
        'ffprobe', '-v', 'quiet',
        '-print_format', 'json',
        '-show_streams', '-show_format',
        str(input_file)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None

    return json.loads(result.stdout)


def extract_stems_ffmpeg(input_file, output_dir, output_format='wav'):
    """
    Extract stems using ffmpeg with channel splitting.

    Despite decoding warnings, ffmpeg can usually extract the audio.
    We use the pan filter to extract each stereo pair.
    """
    input_path = Path(input_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get base name without extension
    base_name = input_path.stem

    # Build ffmpeg command to extract all 4 stems at once
    # Using pan filter to map channel pairs to stereo outputs
    filter_complex = (
        "[0:a]pan=stereo|c0=c0|c1=c1[stem1];"
        "[0:a]pan=stereo|c0=c2|c1=c3[stem2];"
        "[0:a]pan=stereo|c0=c4|c1=c5[stem3];"
        "[0:a]pan=stereo|c0=c6|c1=c7[stem4]"
    )

    cmd = [
        'ffmpeg', '-hide_banner', '-y',
        '-i', str(input_file),
        '-filter_complex', filter_complex,
    ]

    # Add output mappings for each stem
    for i, stem_name in enumerate(STEM_NAMES, 1):
        output_file = output_dir / f"{base_name}_{stem_name}.{output_format}"
        cmd.extend(['-map', f'[stem{i}]'])

        if output_format == 'wav':
            cmd.extend(['-acodec', 'pcm_s16le'])
        elif output_format == 'flac':
            cmd.extend(['-acodec', 'flac'])
        elif output_format == 'mp3':
            cmd.extend(['-acodec', 'libmp3lame', '-q:a', '2'])
        elif output_format == 'aac':
            cmd.extend(['-acodec', 'aac', '-b:a', '256k'])

        cmd.append(str(output_file))

    print(f"Extracting stems from: {input_file}")
    print(f"Output directory: {output_dir}")
    print(f"Output format: {output_format}")
    print()

    # Run ffmpeg (suppress most output but show progress)
    subprocess.run(
        cmd,
        stderr=subprocess.PIPE,
        text=True,
        check=False
    )

    # Check outputs
    success_count = 0
    for i, stem_name in enumerate(STEM_NAMES, 1):
        output_file = output_dir / f"{base_name}_{stem_name}.{output_format}"
        if output_file.exists() and output_file.stat().st_size > 1000:
            size_mb = output_file.stat().st_size / 1024 / 1024
            print(f"  ✓ {stem_name}: {output_file.name} ({size_mb:.2f} MB)")
            success_count += 1
        else:
            print(f"  ✗ {stem_name}: Failed or empty")

    return success_count == 4


def extract_stems_alternative(input_file, output_dir, output_format='wav'):
    """
    Alternative extraction method: first decode to raw audio, then split.

    This approach may work better with problematic AAC streams.
    """
    input_path = Path(input_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_name = input_path.stem
    temp_file = output_dir / f"{base_name}_temp_8ch.wav"

    print(f"Extracting stems (alternative method) from: {input_file}")
    print(f"Output directory: {output_dir}")
    print()

    # Step 1: Decode to 8-channel WAV
    print("Step 1: Decoding to 8-channel WAV...")
    cmd1 = [
        'ffmpeg', '-hide_banner', '-y',
        '-err_detect', 'ignore_err',  # Ignore decoding errors
        '-i', str(input_file),
        '-vn',
        '-acodec', 'pcm_s16le',
        '-ar', '44100',
        str(temp_file)
    ]

    subprocess.run(cmd1, stderr=subprocess.PIPE, text=True, check=False)

    if not temp_file.exists():
        print("  Failed to decode audio!")
        return False

    print(f"  Decoded: {temp_file.stat().st_size / 1024 / 1024:.2f} MB")

    # Step 2: Split channels
    print("\nStep 2: Splitting channels...")

    filter_complex = (
        "[0:a]pan=stereo|c0=c0|c1=c1[stem1];"
        "[0:a]pan=stereo|c0=c2|c1=c3[stem2];"
        "[0:a]pan=stereo|c0=c4|c1=c5[stem3];"
        "[0:a]pan=stereo|c0=c6|c1=c7[stem4]"
    )

    cmd2 = [
        'ffmpeg', '-hide_banner', '-y',
        '-i', str(temp_file),
        '-filter_complex', filter_complex,
    ]

    for i, stem_name in enumerate(STEM_NAMES, 1):
        output_file = output_dir / f"{base_name}_{stem_name}.{output_format}"
        cmd2.extend(['-map', f'[stem{i}]'])

        if output_format == 'wav':
            cmd2.extend(['-acodec', 'pcm_s16le'])
        elif output_format == 'flac':
            cmd2.extend(['-acodec', 'flac'])
        elif output_format == 'mp3':
            cmd2.extend(['-acodec', 'libmp3lame', '-q:a', '2'])

        cmd2.append(str(output_file))

    subprocess.run(cmd2, stderr=subprocess.PIPE, text=True, check=False)

    # Clean up temp file
    if temp_file.exists():
        temp_file.unlink()

    # Check outputs
    success_count = 0
    for i, stem_name in enumerate(STEM_NAMES, 1):
        output_file = output_dir / f"{base_name}_{stem_name}.{output_format}"
        if output_file.exists() and output_file.stat().st_size > 1000:
            size_mb = output_file.stat().st_size / 1024 / 1024
            print(f"  ✓ {stem_name}: {output_file.name} ({size_mb:.2f} MB)")
            success_count += 1
        else:
            print(f"  ✗ {stem_name}: Failed or empty")

    return success_count == 4


def main():
    """CLI to extract stems using ffmpeg or an alternative two-step method."""
    parser = argparse.ArgumentParser(
        description='Extract stems from Engine DJ .stems files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s stems/mysong.stems
  %(prog)s stems/mysong.stems -o output/ -f flac
  %(prog)s stems/*.stems -o output/
        """
    )

    parser.add_argument('input', nargs='+', help='Input .stems file(s)')
    parser.add_argument('-o', '--output', default='output',
                        help='Output directory (default: output)')
    parser.add_argument('-f', '--format', default='wav',
                        choices=['wav', 'flac', 'mp3', 'aac'],
                        help='Output format (default: wav)')
    parser.add_argument('--alternative', action='store_true',
                        help='Use alternative extraction method')

    args = parser.parse_args()

    check_dependencies()

    # Process each input file
    for input_file in args.input:
        input_path = Path(input_file)

        if not input_path.exists():
            print(f"Error: File not found: {input_file}")
            continue

        if input_path.suffix.lower() != '.stems':
            print(f"Warning: {input_file} may not be a .stems file")

        print(f"\n{'='*60}")

        if args.alternative:
            success = extract_stems_alternative(input_path, args.output, args.format)
        else:
            success = extract_stems_ffmpeg(input_path, args.output, args.format)

        if success:
            print("\n✓ Extraction complete!")
        else:
            print("\n✗ Extraction had issues. Trying alternative method...")
            success = extract_stems_alternative(input_path, args.output, args.format)
            if success:
                print("\n✓ Alternative extraction complete!")
            else:
                print("\n✗ Extraction failed!")


if __name__ == '__main__':
    main()
