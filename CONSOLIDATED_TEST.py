#!/usr/bin/env python3
"""
CONSOLIDATED DECRYPTION TESTING SCRIPT
All approaches in one place for easy reference and re-testing

This script consolidates 7 different decryption approaches tested during research.
ALL APPROACHES FAIL - included for documentation and future reference.

CONFIRMED: Encryption is custom/proprietary (no OpenSSL/crypto libs found via Frida)
"""
import struct
from pathlib import Path


def load_keys(keys_file):
    """Load 128-byte hex keys from .keys file"""
    keys = []
    with open(keys_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                keys.append(bytes.fromhex(line))
    return keys


def count_aac_syncs(data, max_check=None):
    """Count AAC sync words (0xFFF*) - used to measure decryption success"""
    max_check = max_check or len(data)
    count = 0
    for i in range(min(max_check, len(data) - 1)):
        word = (data[i] << 8) | data[i+1]
        if (word & 0xfff0) == 0xfff0:
            count += 1
    return count


def decrypt_xor_repeating_key(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 1: XOR with repeating 128-byte key (most promising but still fails)
    
    How it works:
    - Each frame has 128-byte "key" block + 1520-byte encrypted block
    - Extend key to 1520 bytes by repeating: key * 12
    - XOR encrypted data with extended key
    
    Result: ❌ FAILED
    - Produces valid MP4 container
    - FFprobe recognizes format correctly
    - AAC decoder rejects: "Prediction not allowed", "Reserved bit set"
    - Only 0.05 seconds extractable from 6-minute file
    """
    data_start = mdat_start + 8 + 4  # Skip mdat header + seed
    
    decrypted = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        if i >= len(keys):
            break
            
        # Skip 128-byte "key" block
        offset += 128
        
        if offset + 1520 > len(full_file):
            break
        
        # Get encrypted data
        encrypted = full_file[offset:offset+1520]
        
        # Get key and extend to 1520 bytes
        key = keys[i]
        key_extended = (key * 12)[:1520]
        
        # XOR decrypt
        decrypted_frame = bytes(a ^ b for a, b in zip(encrypted, key_extended))
        decrypted.extend(decrypted_frame)
        
        offset += 1520
    
    return bytes(decrypted)


def decrypt_stream_cipher(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 2: Stream cipher with evolving state
    
    How it works:
    - Treat 128-byte blocks as initial states
    - Evolve state to generate keystream
    - XOR encrypted data with keystream
    
    Result: ❌ FAILED
    - Similar false positive AAC sync count (~98-113)
    - No valid audio produced
    """
    data_start = mdat_start + 8 + 4
    
    decrypted = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        if i >= len(keys):
            break
            
        key_block = full_file[offset:offset+128]
        offset += 128
        
        if offset + 1520 > len(full_file):
            break
        
        encrypted = full_file[offset:offset+1520]
        
        # Generate keystream from evolving state
        keystream = bytearray()
        state = bytearray(key_block)
        
        while len(keystream) < 1520:
            for j in range(len(state)):
                state[j] = (state[j] + j + len(keystream)) & 0xFF
            keystream.extend(state)
        
        keystream = bytes(keystream[:1520])
        
        # XOR decrypt
        decrypted_frame = bytes(a ^ b for a, b in zip(encrypted, keystream))
        decrypted.extend(decrypted_frame)
        
        offset += 1520
    
    return bytes(decrypted)


def extract_raw_1520_blocks(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 3: No decryption - use raw 1520-byte blocks
    
    How it works:
    - Skip 128-byte blocks entirely
    - Concatenate 1520-byte blocks as-is
    - Test if data is obfuscated rather than encrypted
    
    Result: ❌ FAILED
    - Similar AAC sync count to other methods
    - Confirms data IS genuinely encrypted
    """
    data_start = mdat_start + 8 + 4
    
    raw_data = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        offset += 128  # Skip "key" block
        
        if offset + 1520 > len(full_file):
            break
        
        raw_data.extend(full_file[offset:offset+1520])
        offset += 1520
    
    return bytes(raw_data)


def extract_128byte_blocks(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 4: Use only 128-byte blocks as audio
    
    How it works:
    - Extract only 128-byte "key" blocks
    - Discard 1520-byte blocks
    - Test if "keys" are actually audio data
    
    Result: ❌ FAILED
    - Random AAC syncs (false positives)
    - Not valid audio
    """
    data_start = mdat_start + 8 + 4
    
    audio_data = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        if offset + 128 > len(full_file):
            break
        
        audio_data.extend(full_file[offset:offset+128])
        offset += 1648  # Skip to next frame
    
    return bytes(audio_data)


def decrypt_xor_partial(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 5: XOR only first 128 bytes, rest plaintext
    
    How it works:
    - XOR first 128 bytes with key
    - Leave remaining 1392 bytes as plaintext
    - Test if only headers are encrypted
    
    Result: ❌ FAILED
    - Similar false positive sync count
    """
    data_start = mdat_start + 8 + 4
    
    decrypted = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        if i >= len(keys):
            break
            
        offset += 128
        
        if offset + 1520 > len(full_file):
            break
        
        encrypted = full_file[offset:offset+1520]
        key = keys[i]
        
        # XOR only first 128 bytes
        xored = bytes(a ^ b for a, b in zip(encrypted[:128], key))
        decrypted.extend(xored)
        decrypted.extend(encrypted[128:])  # Rest plaintext
        
        offset += 1520
    
    return bytes(decrypted)


def extract_combined_frames(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 6: Use complete 1648-byte frames (128 + 1520)
    
    How it works:
    - Concatenate entire frames (key + encrypted)
    - Test if structure interpretation is wrong
    
    Result: ❌ FAILED
    - Same AAC decoding errors
    """
    data_start = mdat_start + 8 + 4
    
    combined = bytearray()
    frame_count = num_frames or len(keys)
    offset = data_start
    
    for i in range(frame_count):
        if offset + 1648 > len(full_file):
            break
        
        combined.extend(full_file[offset:offset+1648])
        offset += 1648
    
    return bytes(combined)


def decrypt_byte_reordering(full_file, keys, mdat_start, num_frames=None):
    """
    APPROACH 7: Byte reordering based on key
    
    How it works:
    - Use key values to determine byte reordering
    - Unscramble data rather than decrypt
    
    Result: ❌ FAILED
    - Fewer AAC syncs (~33) but still invalid
    """
    data_start = mdat_start + 8 + 4
    
    decrypted = bytearray()
    frame_count = min(num_frames or len(keys), len(keys))
    offset = data_start
    
    for i in range(frame_count):
        key_block = full_file[offset:offset+128]
        offset += 128
        
        if offset + 1520 > len(full_file):
            break
        
        data_block = full_file[offset:offset+1520]
        
        # Create reordering based on key
        indices = list(range(128))
        indices.sort(key=lambda x: key_block[x])
        
        # Unscramble each 128-byte chunk
        for chunk_start in range(0, len(data_block), 128):
            chunk = data_block[chunk_start:chunk_start+128]
            if len(chunk) == 128:
                reordered = bytearray(chunk[indices[j % 128]] for j in range(128))
                decrypted.extend(reordered)
            else:
                decrypted.extend(chunk)
        
        offset += 1520
    
    return bytes(decrypted)


def rebuild_mp4(ftyp, free, mdat_data, moov):
    """Rebuild MP4 file with new mdat content"""
    new_mdat_size = len(mdat_data) + 8
    new_mdat = struct.pack('>I', new_mdat_size) + b'mdat' + mdat_data
    return ftyp + free + new_mdat + moov


def main():
    """Run all decryption approaches and compare results"""
    
    # Configuration
    stems_file = 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems'
    keys_file = 'stems/1 0f7da717-a4c6-46be-994e-eca19516836c.keys'
    test_frames = 300  # Test first ~30 seconds
    
    print("=" * 70)
    print("CONSOLIDATED DECRYPTION TEST")
    print("=" * 70)
    print(f"\nFile: {Path(stems_file).name}")
    print(f"Testing: First {test_frames} frames (~30 seconds)\n")
    
    # Load file and keys
    with open(stems_file, 'rb') as f:
        full_file = f.read()
    
    keys = load_keys(keys_file)
    print(f"Loaded {len(keys)} keys\n")
    
    # Find mdat
    mdat_pos = full_file.find(b'mdat')
    mdat_start = mdat_pos - 4
    
    # Extract atoms for MP4 reconstruction
    ftyp = full_file[:28]
    free = full_file[28:36]
    mdat_size = struct.unpack('>I', full_file[mdat_start:mdat_start+4])[0]
    mdat_end = mdat_start + mdat_size
    moov = full_file[mdat_end:]
    
    # Define test approaches
    approaches = [
        ("XOR with repeating key", decrypt_xor_repeating_key, "BEST attempt but still fails"),
        ("Stream cipher", decrypt_stream_cipher, "Evolving keystream"),
        ("Raw 1520-byte blocks", extract_raw_1520_blocks, "No decryption"),
        ("Only 128-byte blocks", extract_128byte_blocks, "Keys as audio"),
        ("XOR first 128 only", decrypt_xor_partial, "Partial encryption"),
        ("Combined 1648 frames", extract_combined_frames, "Full frames"),
        ("Byte reordering", decrypt_byte_reordering, "Scrambling"),
    ]
    
    results = []
    
    print("Testing approaches...\n")
    print("-" * 70)
    
    for name, decrypt_func, description in approaches:
        print(f"\n{name}")
        print(f"  Description: {description}")
        
        # Decrypt
        try:
            decrypted = decrypt_func(full_file, keys, mdat_start, test_frames)
            
            # Analyze
            size = len(decrypted)
            sync_count = count_aac_syncs(decrypted)
            
            # Calculate sync density
            expected_syncs_min = size // 1500  # AAC frames ~300-1500 bytes
            expected_syncs_max = size // 300
            
            print(f"  Output size: {size:,} bytes")
            print(f"  AAC syncs found: {sync_count}")
            print(f"  Expected range: {expected_syncs_min}-{expected_syncs_max} (if valid AAC)")
            
            if sync_count < expected_syncs_min / 10:
                status = "❌ Way too few syncs (encrypted/invalid)"
            elif sync_count > expected_syncs_max * 10:
                status = "❌ Way too many syncs (false positives)"
            elif expected_syncs_min <= sync_count <= expected_syncs_max:
                status = "⚠️  Sync count in range (needs FFmpeg test)"
            else:
                status = "❌ Irregular sync count"
            
            print(f"  Status: {status}")
            
            results.append((name, sync_count, size, status))
            
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            results.append((name, 0, 0, "ERROR"))
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"\n{'Approach':<30} {'Syncs':>8} {'Size':>12} {'Status':>20}")
    print("-" * 70)
    
    for name, syncs, size, status in results:
        status_short = "FAIL" if "❌" in status else "MAYBE" if "⚠️" in status else "ERROR"
        print(f"{name:<30} {syncs:>8} {size:>12,} {status_short:>20}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("""
All approaches produce similar results:
- Irregular AAC sync counts (false positives from random bit patterns)
- FFmpeg AAC decoder rejects all outputs
- Only 0.05-0.09 seconds extractable from full files

This confirms:
1. Data IS genuinely encrypted (not obfuscated)
2. Encryption is NOT simple XOR, stream cipher, or byte reordering
3. No standard crypto libraries used (verified by Frida)
4. Algorithm is custom/proprietary to Engine DJ

Next steps require:
- Binary reverse engineering of Engine DJ Desktop
- Memory dumping during playback to capture decrypted buffers
- Official API/SDK from Denon (unlikely)
    """)


if __name__ == '__main__':
    main()
