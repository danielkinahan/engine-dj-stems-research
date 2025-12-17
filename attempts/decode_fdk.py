#!/usr/bin/env python3
"""
Decode Engine DJ .stems files using libfdk-aac directly via ctypes.
This should handle the PCE-based channel configuration correctly.
"""

import ctypes
from ctypes import c_void_p, c_int, c_uint, c_char_p, POINTER, byref
import struct
import sys
import wave
import subprocess
from pathlib import Path

# Load libfdk-aac
try:
    fdk = ctypes.CDLL("libfdk-aac.so.2")
except OSError:
    fdk = ctypes.CDLL("libfdk-aac.so")

# Define structures
class AACENC_InfoStruct(ctypes.Structure):
    pass  # We only need decoder

class CStreamInfo(ctypes.Structure):
    _fields_ = [
        ("sampleRate", c_int),
        ("frameSize", c_int),
        ("numChannels", c_int),
        ("pChannelType", POINTER(c_int)),
        ("pChannelIndices", POINTER(c_int)),
        ("aacSampleRate", c_int),
        ("profile", c_int),
        ("aot", c_int),  # Audio Object Type
        ("channelConfig", c_int),
        ("bitRate", c_int),
        ("aacSamplesPerFrame", c_int),
        ("aacNumChannels", c_int),
        ("extAot", c_int),
        ("extSampleRate", c_int),
        ("outputDelay", c_uint),
        ("flags", c_uint),
        ("epConfig", c_int),
        ("numLostAccessUnits", c_int),
        ("numTotalBytes", ctypes.c_uint64),
        ("numBadBytes", ctypes.c_uint64),
        ("numTotalAccessUnits", ctypes.c_uint64),
        ("numBadAccessUnits", ctypes.c_uint64),
        ("drcProgRefLev", c_int),
        ("drcPresMode", c_int),
        ("outputLoudness", c_int),
    ]

# Transport types
TT_MP4_RAW = 0
TT_MP4_ADIF = 1
TT_MP4_ADTS = 2
TT_MP4_LATM_MCP1 = 6
TT_MP4_LATM_MCP0 = 7
TT_MP4_LOAS = 10

# Define function prototypes
# HANDLE_AACDECODER aacDecoder_Open(TRANSPORT_TYPE transportFmt, UINT nrOfLayers)
fdk.aacDecoder_Open.argtypes = [c_int, c_uint]
fdk.aacDecoder_Open.restype = c_void_p

# void aacDecoder_Close(HANDLE_AACDECODER self)
fdk.aacDecoder_Close.argtypes = [c_void_p]
fdk.aacDecoder_Close.restype = None

# AAC_DECODER_ERROR aacDecoder_ConfigRaw(HANDLE_AACDECODER self, UCHAR *conf[], const UINT length[])
fdk.aacDecoder_ConfigRaw.argtypes = [c_void_p, POINTER(c_char_p), POINTER(c_uint)]
fdk.aacDecoder_ConfigRaw.restype = c_int

# AAC_DECODER_ERROR aacDecoder_Fill(HANDLE_AACDECODER self, UCHAR *pBuffer[], const UINT bufferSize[], UINT *bytesValid)
fdk.aacDecoder_Fill.argtypes = [c_void_p, POINTER(c_char_p), POINTER(c_uint), POINTER(c_uint)]
fdk.aacDecoder_Fill.restype = c_int

# AAC_DECODER_ERROR aacDecoder_DecodeFrame(HANDLE_AACDECODER self, INT_PCM *pTimeData, const INT timeDataSize, const UINT flags)
fdk.aacDecoder_DecodeFrame.argtypes = [c_void_p, POINTER(ctypes.c_int16), c_int, c_uint]
fdk.aacDecoder_DecodeFrame.restype = c_int

# CStreamInfo* aacDecoder_GetStreamInfo(HANDLE_AACDECODER self)
fdk.aacDecoder_GetStreamInfo.argtypes = [c_void_p]
fdk.aacDecoder_GetStreamInfo.restype = POINTER(CStreamInfo)

# Error codes
AAC_DEC_OK = 0x0000

def extract_aac_samples_from_mp4(mp4_path: str) -> tuple:
    """
    Extract raw AAC access units from MP4 container.
    Returns (samples: list[bytes], asc: bytes, sample_rate: int)
    """
    with open(mp4_path, 'rb') as f:
        data = f.read()

    def find_atom(data, target, start=0, end=None):
        """Find an atom and return its (offset, size, data_start)."""
        if end is None:
            end = len(data)
        pos = start
        while pos < end - 8:
            size = struct.unpack('>I', data[pos:pos+4])[0]
            atom_type = data[pos+4:pos+8]
            if size == 0:
                size = end - pos
            elif size == 1:
                size = struct.unpack('>Q', data[pos+8:pos+16])[0]
            if size < 8:
                break
            if atom_type == target:
                return pos, size, pos + 8
            pos += size
        return None, None, None

    # Find moov
    moov_pos, moov_size, moov_data = find_atom(data, b'moov')
    if moov_pos is None:
        raise ValueError("No moov atom found")

    # Find trak inside moov
    trak_pos, trak_size, trak_data = find_atom(data, b'trak', moov_data, moov_pos + moov_size)
    if trak_pos is None:
        raise ValueError("No trak atom found")

    # Find mdia inside trak
    mdia_pos, mdia_size, mdia_data = find_atom(data, b'mdia', trak_data, trak_pos + trak_size)

    # Find minf inside mdia
    minf_pos, minf_size, minf_data = find_atom(data, b'minf', mdia_data, mdia_pos + mdia_size)

    # Find stbl inside minf
    stbl_pos, stbl_size, stbl_data = find_atom(data, b'stbl', minf_data, minf_pos + minf_size)

    # Extract AudioSpecificConfig from esds
    # First find stsd
    stsd_pos, stsd_size, stsd_data = find_atom(data, b'stsd', stbl_data, stbl_pos + stbl_size)

    # Look for esds anywhere in the stsd region
    asc = None
    esds_search_start = stsd_data
    while esds_search_start < stsd_pos + stsd_size:
        idx = data.find(b'esds', esds_search_start)
        if idx == -1 or idx >= stsd_pos + stsd_size:
            break

        # Skip 'esds' type (4) + version/flags (4)
        esds_data_start = idx + 8

        # Parse ES descriptor
        pos = esds_data_start
        if data[pos] == 0x03:  # ES_Descriptor tag
            pos += 1
            # Skip length (1-4 bytes)
            while data[pos] & 0x80:
                pos += 1
            pos += 1
            pos += 3  # ES_ID + flags

            if data[pos] == 0x04:  # DecoderConfigDescriptor
                pos += 1
                while data[pos] & 0x80:
                    pos += 1
                pos += 1
                pos += 13  # objectType + stream info + bitrates

                if data[pos] == 0x05:  # DecoderSpecificInfo (ASC)
                    pos += 1
                    asc_len = 0
                    while data[pos] & 0x80:
                        asc_len = (asc_len << 7) | (data[pos] & 0x7f)
                        pos += 1
                    asc_len = (asc_len << 7) | data[pos]
                    pos += 1
                    asc = data[pos:pos + asc_len]
                    break

        esds_search_start = idx + 1

    if asc is None:
        raise ValueError("Could not find AudioSpecificConfig")

    print(f"AudioSpecificConfig: {asc.hex()}")

    # Parse ASC to get sample rate
    asc_bits = int.from_bytes(asc[:2], 'big')
    sri = (asc_bits >> 7) & 0x0F
    sample_rates = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
                   16000, 12000, 11025, 8000, 7350]
    sample_rate = sample_rates[sri] if sri < len(sample_rates) else 44100

    # Find stsz (sample sizes)
    stsz_pos, _stsz_size, stsz_data = find_atom(data, b'stsz', stbl_data, stbl_pos + stbl_size)
    if stsz_pos is None:
        raise ValueError("No stsz atom found")

    # Parse stsz: version(1) + flags(3) + sample_size(4) + sample_count(4) + [sizes]
    default_sample_size = struct.unpack('>I', data[stsz_data+4:stsz_data+8])[0]
    sample_count = struct.unpack('>I', data[stsz_data+8:stsz_data+12])[0]

    sample_sizes = []
    if default_sample_size == 0:
        for i in range(sample_count):
            size = struct.unpack('>I', data[stsz_data+12+i*4:stsz_data+16+i*4])[0]
            sample_sizes.append(size)
    else:
        sample_sizes = [default_sample_size] * sample_count

    print(f"Found {len(sample_sizes)} samples")

    # Find stco or co64 (chunk offsets)
    stco_pos, _stco_size, stco_data = find_atom(data, b'stco', stbl_data, stbl_pos + stbl_size)
    co64 = False
    if stco_pos is None:
        stco_pos, _stco_size, stco_data = find_atom(data, b'co64', stbl_data, stbl_pos + stbl_size)
        co64 = True

    if stco_pos is None:
        raise ValueError("No stco/co64 atom found")

    chunk_count = struct.unpack('>I', data[stco_data+4:stco_data+8])[0]
    chunk_offsets = []
    for i in range(chunk_count):
        if co64:
            offset = struct.unpack('>Q', data[stco_data+8+i*8:stco_data+16+i*8])[0]
        else:
            offset = struct.unpack('>I', data[stco_data+8+i*4:stco_data+12+i*4])[0]
        chunk_offsets.append(offset)

    # Find stsc (sample-to-chunk mapping)
    stsc_pos, _stsc_size, stsc_data = find_atom(data, b'stsc', stbl_data, stbl_pos + stbl_size)
    if stsc_pos is None:
        raise ValueError("No stsc atom found")

    entry_count = struct.unpack('>I', data[stsc_data+4:stsc_data+8])[0]
    stsc_entries = []
    for i in range(entry_count):
        first_chunk = struct.unpack('>I', data[stsc_data+8+i*12:stsc_data+12+i*12])[0]
        samples_per_chunk = struct.unpack('>I', data[stsc_data+12+i*12:stsc_data+16+i*12])[0]
        sample_desc_idx = struct.unpack('>I', data[stsc_data+16+i*12:stsc_data+20+i*12])[0]
        stsc_entries.append((first_chunk, samples_per_chunk, sample_desc_idx))

    # Extract samples
    samples = []
    sample_idx = 0

    for chunk_idx in range(len(chunk_offsets)):
        chunk_num = chunk_idx + 1  # 1-based

        # Find samples per chunk for this chunk
        samples_in_chunk = 0
        for i, (first, spc, _) in enumerate(stsc_entries):
            if first <= chunk_num:
                if i + 1 < len(stsc_entries) and stsc_entries[i+1][0] <= chunk_num:
                    continue
                samples_in_chunk = spc
                break

        offset = chunk_offsets[chunk_idx]
        for _ in range(samples_in_chunk):
            if sample_idx >= len(sample_sizes):
                break
            size = sample_sizes[sample_idx]
            sample_data = data[offset:offset+size]
            samples.append(bytes(sample_data))
            offset += size
            sample_idx += 1

    return samples, asc, sample_rate


def decode_stems_fdk(input_path: str, output_dir: str = None):
    """Decode a .stems file using libfdk-aac directly."""

    input_path = Path(input_path)
    if output_dir is None:
        output_dir = input_path.parent / input_path.stem
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    stem_names = ['drums', 'bass', 'melody', 'vocals']

    print(f"Processing: {input_path.name}")
    print("=" * 60)

    # Extract raw AAC samples
    print("\nStep 1: Extracting AAC samples from MP4...")
    samples, asc, sample_rate = extract_aac_samples_from_mp4(str(input_path))
    print(f"  Sample rate: {sample_rate} Hz")
    print(f"  ASC: {asc.hex()}")

    # Open decoder with ADTS transport type
    # ADTS should handle PCE in the stream better
    print("\nStep 2: Initializing FDK-AAC decoder...")
    decoder = fdk.aacDecoder_Open(TT_MP4_ADTS, 1)
    if not decoder:
        print("Failed to open decoder")
        return False

    # Configure with ASC
    # The original ASC has PCE embedded, but fdk-aac might not handle it well
    # Try with original first, then fallback to minimal ASC
    asc_to_try = [
        asc,  # Original full ASC
        asc[:2],  # Minimal (just AOT + SRI + channel config 0)
        bytes.fromhex('1210'),  # AAC-LC, 44100Hz, stereo
        bytes.fromhex('1238'),  # AAC-LC, 44100Hz, 8ch (7.1)
    ]

    config_ok = False
    for i, test_asc in enumerate(asc_to_try):
        asc_ptr = ctypes.cast(ctypes.c_char_p(test_asc), ctypes.c_char_p)
        asc_len = ctypes.c_uint(len(test_asc))

        err = fdk.aacDecoder_ConfigRaw(decoder, byref(asc_ptr), byref(asc_len))
        if err == AAC_DEC_OK:
            print(f"  ConfigRaw succeeded with ASC variant {i}: {test_asc.hex()}")
            config_ok = True
            break
        else:
            print(f"  ConfigRaw variant {i} failed: 0x{err:04x} (ASC: {test_asc.hex()})")

    if not config_ok:
        print("All ASC variants failed")
        fdk.aacDecoder_Close(decoder)
        return False

    # Get stream info
    stream_info = fdk.aacDecoder_GetStreamInfo(decoder)
    print(f"  Channels: {stream_info.contents.numChannels}")
    print(f"  Sample rate: {stream_info.contents.sampleRate}")
    print(f"  Frame size: {stream_info.contents.frameSize}")

    # Decode all samples
    print("\nStep 3: Decoding...")

    # Output buffer - max 8 channels * 2048 samples
    output_buffer = (ctypes.c_int16 * (8 * 2048))()

    all_pcm = []
    decoded_frames = 0
    error_count = 0

    for i, sample in enumerate(samples):
        # Fill buffer
        buf_ptr = ctypes.cast(ctypes.c_char_p(sample), ctypes.c_char_p)
        buf_size = ctypes.c_uint(len(sample))
        bytes_valid = ctypes.c_uint(len(sample))

        err = fdk.aacDecoder_Fill(decoder, byref(buf_ptr), byref(buf_size), byref(bytes_valid))
        if err != AAC_DEC_OK:
            error_count += 1
            continue

        # Decode frame
        err = fdk.aacDecoder_DecodeFrame(decoder, output_buffer, len(output_buffer), 0)

        if err == AAC_DEC_OK:
            # Get updated stream info
            info = fdk.aacDecoder_GetStreamInfo(decoder)
            num_channels = info.contents.numChannels
            frame_size = info.contents.frameSize

            if num_channels > 0 and frame_size > 0:
                # Extract PCM data
                pcm_data = bytes(output_buffer[:num_channels * frame_size * 2])
                all_pcm.append(pcm_data)
                decoded_frames += 1
        else:
            error_count += 1

        if (i + 1) % 1000 == 0:
            print(f"  Processed {i + 1}/{len(samples)} samples...")

    fdk.aacDecoder_Close(decoder)

    print(f"\n  Decoded {decoded_frames} frames ({error_count} errors)")

    if not all_pcm:
        print("No audio decoded!")
        return False

    # Get final channel count
    info = fdk.aacDecoder_GetStreamInfo(decoder) if decoder else None
    num_channels = 8  # Assume 8 channels for stems

    # Combine all PCM data
    full_pcm = b''.join(all_pcm)
    print(f"  Total PCM: {len(full_pcm) / 1024 / 1024:.2f} MB")

    # Save full 8-channel file first
    full_wav_path = output_dir / "_full_8ch.wav"
    with wave.open(str(full_wav_path), 'wb') as wav:
        wav.setnchannels(num_channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(full_pcm)

    print("\nStep 4: Splitting into stems...")

    # Use ffmpeg to split channels
    for i, name in enumerate(stem_names):
        left = i * 2
        right = i * 2 + 1

        output_path = output_dir / f'{name}.wav'

        cmd = [
            'ffmpeg', '-y',
            '-i', str(full_wav_path),
            '-af', f'pan=stereo|c0=c{left}|c1=c{right}',
            str(output_path)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode == 0 and output_path.exists():
            print(f"  ✓ {name}.wav ({output_path.stat().st_size / 1024 / 1024:.2f} MB)")
        else:
            print(f"  ✗ {name}: Split failed")

    # Clean up full file
    full_wav_path.unlink()

    print(f"\nOutput: {output_dir}")
    return True


def main():
    if len(sys.argv) < 2:
        print("Engine DJ Stems Decoder using libfdk-aac")
        print("=" * 50)
        print("\nUsage: python decode_fdk.py <stems_file> [output_dir]")
        print("\nExample:")
        print('  python decode_fdk.py "stems/1 xyz.stems"')
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    success = decode_stems_fdk(input_file, output_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
