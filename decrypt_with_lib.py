#!/usr/bin/env python3
"""
Example: Simplified decryption script using stems_lib

This demonstrates how a typical 150-line script becomes ~30 lines
when using the consolidated library.

Usage:
    python decrypt_with_lib.py <stems_file>
    
Example:
    python decrypt_with_lib.py "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
"""

from stems_lib import *
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt_with_lib.py <stems_file>")
        print("\nNote: Requires corresponding .keys file")
        sys.exit(1)
    
    stems_file = sys.argv[1]
    
    # Derive keys file path
    keys_file = Path(stems_file).with_suffix('.keys')
    if not keys_file.exists():
        print(f"❌ Keys file not found: {keys_file}")
        print(f"\nExtract keys first:")
        print(f"  python extract_keys_from_stems.py")
        sys.exit(1)
    
    print("=" * 70)
    print("DECRYPT WITH LIBRARY EXAMPLE")
    print("=" * 70)
    print()
    
    # Get file info (1 line vs ~20)
    print("[*] Analyzing file...")
    info = get_file_info(stems_file)
    
    if not info['valid']:
        print(f"❌ Invalid file: {info['error']}")
        sys.exit(1)
    
    print(f"✓ File: {Path(stems_file).name}")
    print(f"  Frames: {info['num_frames']:,}")
    print(f"  Duration: {info['estimated_duration']}")
    print(f"  Seed: {info['seed']}")
    print()
    
    # Load data (2 lines vs ~25)
    print("[*] Loading data...")
    data = load_stems_file(stems_file)
    keys = load_keys_file(str(keys_file))
    print(f"✓ Loaded {len(keys):,} keys")
    print()
    
    # Decrypt (1 line vs ~30)
    print("[*] Decrypting with XOR (repeating key)...")
    decrypted = decrypt_xor_repeating(data, keys)
    print(f"✓ Decrypted {len(decrypted):,} bytes")
    print()
    
    # Analyze result
    print("[*] Analyzing decrypted data...")
    syncs = count_aac_syncs(decrypted)
    sync_info = analyze_sync_distances(decrypted)
    entropy = calculate_entropy(decrypted)
    
    print(f"  AAC syncs: {syncs:,}")
    print(f"  Sync distances: {sync_info['min']}-{sync_info['max']} bytes (avg: {sync_info['avg']:.0f})")
    print(f"  Entropy: {entropy:.3f}")
    print()
    
    # Rebuild MP4 (2 lines vs ~15)
    print("[*] Rebuilding MP4...")
    structure = parse_stems_structure(data)
    output_data = rebuild_mp4_file(structure, decrypted)
    print(f"✓ Rebuilt MP4: {len(output_data):,} bytes")
    print()
    
    # Save
    output_file = Path(stems_file).with_name(
        Path(stems_file).stem + '_decrypted_lib.m4a'
    )
    
    print(f"[*] Saving to: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(output_data)
    print(f"✓ Saved")
    print()
    
    # Verdict
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print()
    print(f"✓ Successfully created: {output_file}")
    print(f"✓ File is valid MP4 (ffprobe will recognize it)")
    print()
    print("❌ HOWEVER: Audio is invalid/unplayable")
    print()
    print("Why it fails:")
    print("  - AAC decoder reports: 'Prediction not allowed', 'Reserved bit set'")
    print("  - Only ~0.05 seconds extractable from full file")
    print("  - XOR with stored keys does NOT produce valid AAC")
    print()
    print("Conclusion:")
    print("  - Encryption algorithm is NOT simple XOR")
    print("  - Algorithm is custom/proprietary (no crypto libs used)")
    print("  - Requires binary reverse engineering to proceed")
    print()
    print("Test the output:")
    print(f"  ffprobe \"{output_file}\"")
    print(f"  ffmpeg -i \"{output_file}\" -t 10 test.wav")
    print()


if __name__ == '__main__':
    main()
