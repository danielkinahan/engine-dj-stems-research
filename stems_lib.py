#!/usr/bin/env python3
"""
stems_lib.py - Consolidated library for Engine DJ .stems file handling

This module contains all common functions used across the research scripts,
eliminating 100+ instances of duplicated code.

Usage:
    from stems_lib import *
    
    # Load file
    stems_data = load_stems_file("path/to/file.stems")
    
    # Extract keys
    keys = extract_keys_from_stems(stems_data)
    
    # Decrypt (XOR - doesn't work but included for reference)
    decrypted = decrypt_xor_repeating(stems_data, keys)
    
    # Rebuild MP4
    new_mp4 = rebuild_mp4_file(stems_data, decrypted)
"""

import struct
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass


# ============================================================================
# CONSTANTS - File Format Specification
# ============================================================================

# Atom sizes
FTYP_SIZE = 28
FREE_SIZE = 8
MDAT_HEADER_SIZE = 8
SEED_SIZE = 4

# Frame structure
KEY_BLOCK_SIZE = 128      # Per-frame "key" block (plaintext, NOT XOR keys)
ENCRYPTED_SIZE = 1520     # Per-frame encrypted audio data
FRAME_SIZE = KEY_BLOCK_SIZE + ENCRYPTED_SIZE  # 1648 bytes total

# Target format (what decrypted audio should be)
TARGET_CODEC = 'AAC-LC'
TARGET_CHANNELS = 8       # 4 stereo pairs
TARGET_SAMPLE_RATE = 44100
TARGET_BITRATE = 640000   # ~640 kbps

# Channel layout
CHANNEL_LAYOUT = {
    'drums': (0, 1),      # Channels 0-1
    'bass': (2, 3),       # Channels 2-3
    'melody': (4, 5),     # Channels 4-5
    'vocals': (6, 7),     # Channels 6-7
}

# AAC sync word (used to detect valid AAC frames)
AAC_SYNC_MASK = 0xFFF0
AAC_SYNC_WORD = 0xFFF0


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class StemsFileStructure:
    """Parsed structure of a .stems file"""
    ftyp: bytes
    free: bytes
    mdat_offset: int
    mdat_size: int
    seed: int
    frames_offset: int
    num_frames: int
    moov: bytes
    full_data: bytes


@dataclass
class FrameData:
    """Single frame from .stems file"""
    index: int
    key_block: bytes      # 128 bytes
    encrypted: bytes      # 1520 bytes
    offset: int


# ============================================================================
# FILE I/O
# ============================================================================

def load_stems_file(filepath: str) -> bytes:
    """Load entire .stems file into memory"""
    with open(filepath, 'rb') as f:
        return f.read()


def load_keys_file(filepath: str) -> List[bytes]:
    """
    Load keys from a .keys file
    
    Format: One hex string per line (256 chars = 128 bytes)
    Lines starting with # are comments
    """
    keys = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                keys.append(bytes.fromhex(line))
    return keys


def save_keys_file(filepath: str, keys: List[bytes], metadata: Optional[Dict] = None):
    """
    Save keys to a .keys file
    
    Args:
        filepath: Output path
        keys: List of 128-byte key blocks
        metadata: Optional dict with seed, num_frames, etc.
    """
    with open(filepath, 'w') as f:
        if metadata:
            f.write(f"# Engine DJ Stems Keys\n")
            for key, value in metadata.items():
                f.write(f"# {key}: {value}\n")
            f.write(f"# Keys: {len(keys)}\n\n")
        
        for i, key in enumerate(keys):
            f.write(key.hex() + '\n')


# ============================================================================
# FILE STRUCTURE PARSING
# ============================================================================

def parse_stems_structure(data: bytes) -> StemsFileStructure:
    """
    Parse .stems file structure
    
    Returns StemsFileStructure with all components identified
    """
    # Extract atoms
    ftyp = data[:FTYP_SIZE]
    free = data[FTYP_SIZE:FTYP_SIZE + FREE_SIZE]
    
    # Find mdat
    mdat_pos = data.find(b'mdat')
    if mdat_pos == -1:
        raise ValueError("No mdat atom found")
    
    mdat_offset = mdat_pos - 4
    mdat_size = struct.unpack('>I', data[mdat_offset:mdat_offset+4])[0]
    mdat_end = mdat_offset + mdat_size
    
    # Extract seed (first 4 bytes of mdat data)
    seed_offset = mdat_offset + MDAT_HEADER_SIZE
    seed = struct.unpack('>I', data[seed_offset:seed_offset+4])[0]
    
    # Calculate frames
    frames_offset = seed_offset + SEED_SIZE
    mdat_data_size = mdat_size - MDAT_HEADER_SIZE - SEED_SIZE
    num_frames = mdat_data_size // FRAME_SIZE
    
    # Extract moov
    moov = data[mdat_end:]
    
    return StemsFileStructure(
        ftyp=ftyp,
        free=free,
        mdat_offset=mdat_offset,
        mdat_size=mdat_size,
        seed=seed,
        frames_offset=frames_offset,
        num_frames=num_frames,
        moov=moov,
        full_data=data
    )


def extract_frame(data: bytes, structure: StemsFileStructure, frame_index: int) -> FrameData:
    """Extract a single frame by index"""
    if frame_index >= structure.num_frames:
        raise IndexError(f"Frame {frame_index} out of range (max: {structure.num_frames-1})")
    
    offset = structure.frames_offset + (frame_index * FRAME_SIZE)
    key_block = data[offset:offset + KEY_BLOCK_SIZE]
    encrypted = data[offset + KEY_BLOCK_SIZE:offset + FRAME_SIZE]
    
    return FrameData(
        index=frame_index,
        key_block=key_block,
        encrypted=encrypted,
        offset=offset
    )


def extract_all_frames(data: bytes, structure: StemsFileStructure) -> List[FrameData]:
    """Extract all frames from file"""
    return [extract_frame(data, structure, i) for i in range(structure.num_frames)]


def extract_keys_from_stems(data: bytes) -> Tuple[List[bytes], int]:
    """
    Extract all 128-byte "key" blocks from .stems file
    
    Returns:
        (keys, seed) tuple
    """
    structure = parse_stems_structure(data)
    keys = []
    
    offset = structure.frames_offset
    for i in range(structure.num_frames):
        key_block = data[offset:offset + KEY_BLOCK_SIZE]
        keys.append(key_block)
        offset += FRAME_SIZE
    
    return keys, structure.seed


# ============================================================================
# DECRYPTION FUNCTIONS (ALL FAIL - Included for Reference)
# ============================================================================

def decrypt_xor_repeating(data: bytes, keys: List[bytes], num_frames: Optional[int] = None) -> bytes:
    """
    APPROACH 1: XOR with repeating 128-byte key
    
    Result: ❌ FAILED - Produces invalid AAC
    
    This was the most promising approach but produces AAC frames that decoders
    reject with errors like "Prediction not allowed", "Reserved bit set".
    """
    structure = parse_stems_structure(data)
    frame_count = min(num_frames or structure.num_frames, len(keys))
    
    decrypted = bytearray()
    offset = structure.frames_offset
    
    for i in range(frame_count):
        # Skip key block
        offset += KEY_BLOCK_SIZE
        
        # Get encrypted data
        encrypted = data[offset:offset + ENCRYPTED_SIZE]
        
        # Extend key to 1520 bytes
        key = keys[i]
        key_extended = (key * 12)[:ENCRYPTED_SIZE]
        
        # XOR decrypt
        decrypted_frame = bytes(a ^ b for a, b in zip(encrypted, key_extended))
        decrypted.extend(decrypted_frame)
        
        offset += ENCRYPTED_SIZE
    
    return bytes(decrypted)


def decrypt_stream_cipher(data: bytes, keys: List[bytes], num_frames: Optional[int] = None) -> bytes:
    """
    APPROACH 2: Stream cipher with evolving state
    
    Result: ❌ FAILED - Similar false positive AAC syncs
    """
    structure = parse_stems_structure(data)
    frame_count = min(num_frames or structure.num_frames, len(keys))
    
    decrypted = bytearray()
    offset = structure.frames_offset
    
    for i in range(frame_count):
        key_block = data[offset:offset + KEY_BLOCK_SIZE]
        offset += KEY_BLOCK_SIZE
        
        encrypted = data[offset:offset + ENCRYPTED_SIZE]
        
        # Generate keystream from evolving state
        keystream = bytearray()
        state = bytearray(key_block)
        
        while len(keystream) < ENCRYPTED_SIZE:
            for j in range(len(state)):
                state[j] = (state[j] + j + len(keystream)) & 0xFF
            keystream.extend(state)
        
        keystream = bytes(keystream[:ENCRYPTED_SIZE])
        
        # XOR decrypt
        decrypted_frame = bytes(a ^ b for a, b in zip(encrypted, keystream))
        decrypted.extend(decrypted_frame)
        
        offset += ENCRYPTED_SIZE
    
    return bytes(decrypted)


def extract_raw_encrypted(data: bytes, num_frames: Optional[int] = None) -> bytes:
    """
    APPROACH 3: No decryption - raw 1520-byte blocks
    
    Result: ❌ FAILED - Confirms data is genuinely encrypted
    """
    structure = parse_stems_structure(data)
    frame_count = num_frames or structure.num_frames
    
    raw_data = bytearray()
    offset = structure.frames_offset
    
    for i in range(frame_count):
        offset += KEY_BLOCK_SIZE  # Skip key block
        raw_data.extend(data[offset:offset + ENCRYPTED_SIZE])
        offset += ENCRYPTED_SIZE
    
    return bytes(raw_data)


def extract_key_blocks_only(data: bytes, num_frames: Optional[int] = None) -> bytes:
    """
    APPROACH 4: Use only 128-byte blocks as audio
    
    Result: ❌ FAILED - Not valid audio
    """
    structure = parse_stems_structure(data)
    frame_count = num_frames or structure.num_frames
    
    audio_data = bytearray()
    offset = structure.frames_offset
    
    for i in range(frame_count):
        audio_data.extend(data[offset:offset + KEY_BLOCK_SIZE])
        offset += FRAME_SIZE
    
    return bytes(audio_data)


# ============================================================================
# MP4 RECONSTRUCTION
# ============================================================================

def rebuild_mp4_file(structure: StemsFileStructure, mdat_audio_data: bytes) -> bytes:
    """
    Rebuild MP4 file with new mdat content
    
    Args:
        structure: Parsed file structure
        mdat_audio_data: New audio data (decrypted or modified)
    
    Returns:
        Complete MP4 file bytes
    """
    # Build new mdat atom
    new_mdat_size = len(mdat_audio_data) + MDAT_HEADER_SIZE
    new_mdat = struct.pack('>I', new_mdat_size) + b'mdat' + mdat_audio_data
    
    # Reassemble file
    return structure.ftyp + structure.free + new_mdat + structure.moov


def rebuild_mp4_simple(ftyp: bytes, free: bytes, mdat_data: bytes, moov: bytes) -> bytes:
    """Simple MP4 rebuild (legacy interface for compatibility)"""
    new_mdat_size = len(mdat_data) + 8
    new_mdat = struct.pack('>I', new_mdat_size) + b'mdat' + mdat_data
    return ftyp + free + new_mdat + moov


# ============================================================================
# ANALYSIS UTILITIES
# ============================================================================

def count_aac_syncs(data: bytes, max_check: Optional[int] = None) -> int:
    """
    Count AAC sync words (0xFFF*) in data
    
    Note: In encrypted .stems files, these are FALSE POSITIVES
    (random 0xFFF bit patterns, not actual AAC sync words)
    
    Real AAC should have syncs every 300-1500 bytes consistently.
    """
    max_check = max_check or len(data)
    count = 0
    
    for i in range(min(max_check, len(data) - 1)):
        word = (data[i] << 8) | data[i+1]
        if (word & AAC_SYNC_MASK) == AAC_SYNC_WORD:
            count += 1
    
    return count


def find_aac_syncs(data: bytes, max_syncs: int = 100) -> List[int]:
    """Find positions of AAC sync words"""
    positions = []
    
    for i in range(len(data) - 1):
        if len(positions) >= max_syncs:
            break
        
        word = (data[i] << 8) | data[i+1]
        if (word & AAC_SYNC_MASK) == AAC_SYNC_WORD:
            positions.append(i)
    
    return positions


def analyze_sync_distances(data: bytes) -> Dict[str, float]:
    """
    Analyze distances between AAC sync words
    
    Returns dict with min, max, avg, median distances
    """
    positions = find_aac_syncs(data)
    
    if len(positions) < 2:
        return {'count': len(positions), 'min': 0, 'max': 0, 'avg': 0, 'median': 0}
    
    distances = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
    distances.sort()
    
    return {
        'count': len(positions),
        'min': min(distances),
        'max': max(distances),
        'avg': sum(distances) / len(distances),
        'median': distances[len(distances)//2]
    }


def calculate_entropy(data: bytes, sample_size: int = 256) -> float:
    """
    Calculate byte entropy (0.0 to 1.0)
    
    1.0 = maximum entropy (all 256 byte values present equally)
    0.0 = minimum entropy (single byte value repeated)
    """
    if len(data) < sample_size:
        sample = data
    else:
        sample = data[:sample_size]
    
    unique_bytes = len(set(sample))
    return unique_bytes / 256.0


# ============================================================================
# VALIDATION
# ============================================================================

def validate_stems_file(data: bytes) -> Tuple[bool, str]:
    """
    Validate .stems file structure
    
    Returns:
        (is_valid, error_message) tuple
    """
    if len(data) < 100:
        return False, "File too small"
    
    # Check ftyp
    if data[4:8] != b'ftyp':
        return False, "Invalid ftyp atom"
    
    # Check for mdat
    if b'mdat' not in data:
        return False, "No mdat atom found"
    
    # Check for moov
    if b'moov' not in data:
        return False, "No moov atom found"
    
    try:
        structure = parse_stems_structure(data)
        
        if structure.num_frames < 1:
            return False, f"Invalid frame count: {structure.num_frames}"
        
        if structure.seed == 0:
            return False, "Invalid seed (0x00000000)"
        
        return True, "Valid"
    
    except Exception as e:
        return False, f"Parse error: {e}"


def get_file_info(filepath: str) -> Dict:
    """Get comprehensive file information"""
    data = load_stems_file(filepath)
    is_valid, msg = validate_stems_file(data)
    
    if not is_valid:
        return {'valid': False, 'error': msg}
    
    structure = parse_stems_structure(data)
    
    # Estimate duration (rough calculation)
    # AAC-LC at 44100 Hz, typical frame ~1024 samples
    samples_per_frame = 1024
    duration_seconds = (structure.num_frames * samples_per_frame) / TARGET_SAMPLE_RATE
    
    return {
        'valid': True,
        'filepath': filepath,
        'size': len(data),
        'seed': f"0x{structure.seed:08x}",
        'num_frames': structure.num_frames,
        'estimated_duration': f"{duration_seconds:.2f} seconds ({duration_seconds/60:.2f} minutes)",
        'ftyp_size': len(structure.ftyp),
        'mdat_size': structure.mdat_size,
        'moov_size': len(structure.moov),
    }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def quick_extract_keys(stems_filepath: str, output_filepath: Optional[str] = None) -> List[bytes]:
    """
    Quick function to extract keys from .stems file
    
    Args:
        stems_filepath: Path to .stems file
        output_filepath: Optional path to save .keys file
    
    Returns:
        List of 128-byte key blocks
    """
    data = load_stems_file(stems_filepath)
    keys, seed = extract_keys_from_stems(data)
    
    if output_filepath:
        structure = parse_stems_structure(data)
        metadata = {
            'source': stems_filepath,
            'seed': f"0x{seed:08x}",
            'frames': structure.num_frames,
        }
        save_keys_file(output_filepath, keys, metadata)
    
    return keys


def quick_decrypt_xor(stems_filepath: str, keys_filepath: str, output_filepath: str):
    """
    Quick XOR decryption (doesn't work but convenient for testing)
    
    Args:
        stems_filepath: Input .stems file
        keys_filepath: Input .keys file
        output_filepath: Output .m4a file
    """
    data = load_stems_file(stems_filepath)
    keys = load_keys_file(keys_filepath)
    structure = parse_stems_structure(data)
    
    decrypted = decrypt_xor_repeating(data, keys)
    output = rebuild_mp4_file(structure, decrypted)
    
    with open(output_filepath, 'wb') as f:
        f.write(output)
    
    print(f"[+] Decrypted {len(keys):,} frames")
    print(f"[+] Output: {output_filepath} ({len(output):,} bytes)")
    print(f"[!] Note: This produces invalid AAC (decryption algorithm unknown)")


# ============================================================================
# MAIN - Demo Usage
# ============================================================================

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python stems_lib.py <stems_file>")
        print("\nThis is a library module. Import it in your scripts:")
        print("  from stems_lib import *")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    print("=" * 70)
    print("STEMS FILE ANALYSIS")
    print("=" * 70)
    print()
    
    info = get_file_info(filepath)
    
    if not info['valid']:
        print(f"❌ Invalid file: {info['error']}")
        sys.exit(1)
    
    print(f"File: {info['filepath']}")
    print(f"Size: {info['size']:,} bytes")
    print(f"Seed: {info['seed']}")
    print(f"Frames: {info['num_frames']:,}")
    print(f"Duration: {info['estimated_duration']}")
    print()
    print("Structure:")
    print(f"  ftyp: {info['ftyp_size']} bytes")
    print(f"  mdat: {info['mdat_size']:,} bytes")
    print(f"  moov: {info['moov_size']:,} bytes")
    print()
    
    # Load and analyze
    data = load_stems_file(filepath)
    keys, seed = extract_keys_from_stems(data)
    
    print(f"Extracted {len(keys):,} key blocks")
    print()
    
    # Test decryption approaches
    print("Testing decryption approaches:")
    print()
    
    test_frames = min(300, len(keys))
    
    approaches = [
        ("XOR repeating key", lambda d, k, n: decrypt_xor_repeating(d, k, n)),
        ("Stream cipher", lambda d, k, n: decrypt_stream_cipher(d, k, n)),
        ("Raw encrypted", lambda d, k, n: extract_raw_encrypted(d, n)),
        ("Key blocks only", lambda d, k, n: extract_key_blocks_only(d, n)),
    ]
    
    for name, func in approaches:
        result = func(data, keys, test_frames)
        syncs = count_aac_syncs(result)
        entropy = calculate_entropy(result)
        
        print(f"{name:20s}: {len(result):8,} bytes, {syncs:4d} syncs, entropy {entropy:.2f}")
    
    print()
    print("All approaches fail (custom encryption algorithm)")
