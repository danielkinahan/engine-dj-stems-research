#!/usr/bin/env python3
"""
Decode Engine DJ .stems files using libfdk-aac with ADTS transport.
Extract ADTS stream with ffmpeg, then decode with fdk-aac.
"""

import ctypes
from ctypes import c_void_p, c_int, c_uint, c_char_p, POINTER, byref
import sys
import os
import wave
import subprocess
import tempfile
from pathlib import Path

# Load libfdk-aac
try:
    fdk = ctypes.CDLL("libfdk-aac.so.2")
except OSError:
    fdk = ctypes.CDLL("libfdk-aac.so")

# Define CStreamInfo structure
class CStreamInfo(ctypes.Structure):
    _fields_ = [
        ("sampleRate", c_int),
        ("frameSize", c_int),
        ("numChannels", c_int),
        ("pChannelType", POINTER(c_int)),
        ("pChannelIndices", POINTER(c_int)),
        ("aacSampleRate", c_int),
        ("profile", c_int),
        ("aot", c_int),
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
TT_MP4_ADTS = 2

# Decoder flags
AACDEC_FLUSH = 2
AACDEC_INTR = 4
AACDEC_CLRHIST = 8

# Define function prototypes
fdk.aacDecoder_Open.argtypes = [c_int, c_uint]
fdk.aacDecoder_Open.restype = c_void_p

fdk.aacDecoder_Close.argtypes = [c_void_p]
fdk.aacDecoder_Close.restype = None

fdk.aacDecoder_Fill.argtypes = [c_void_p, POINTER(c_char_p), POINTER(c_uint), POINTER(c_uint)]
fdk.aacDecoder_Fill.restype = c_int

fdk.aacDecoder_DecodeFrame.argtypes = [c_void_p, POINTER(ctypes.c_int16), c_int, c_uint]
fdk.aacDecoder_DecodeFrame.restype = c_int

fdk.aacDecoder_GetStreamInfo.argtypes = [c_void_p]
fdk.aacDecoder_GetStreamInfo.restype = POINTER(CStreamInfo)

# Error codes
AAC_DEC_OK = 0x0000
AAC_DEC_NOT_ENOUGH_BITS = 0x1002
AAC_DEC_TRANSPORT_SYNC_ERROR = 0x4001


def decode_adts_with_fdk(adts_path: str) -> tuple:
    """
    Decode ADTS file using libfdk-aac.
    Returns (pcm_data: bytes, num_channels: int, sample_rate: int)
    """

    with open(adts_path, 'rb') as f:
        adts_data = f.read()

    print(f"  ADTS size: {len(adts_data) / 1024 / 1024:.2f} MB")

    # Open decoder for ADTS
    decoder = fdk.aacDecoder_Open(TT_MP4_ADTS, 1)
    if not decoder:
        raise RuntimeError("Failed to open decoder")

    # Output buffer - max 8 channels * 2048 samples
    output_buffer = (ctypes.c_int16 * (8 * 2048))()

    all_pcm = []
    decoded_frames = 0
    error_count = 0
    num_channels = 0
    sample_rate = 0

    # Process data in chunks
    chunk_size = 8192
    pos = 0

    while pos < len(adts_data):
        # Feed data to decoder
        chunk = adts_data[pos:pos + chunk_size]
        if not chunk:
            break

        buf_ptr = ctypes.cast(ctypes.c_char_p(chunk), ctypes.c_char_p)
        buf_size = ctypes.c_uint(len(chunk))
        bytes_valid = ctypes.c_uint(len(chunk))

        err = fdk.aacDecoder_Fill(decoder, byref(buf_ptr), byref(buf_size), byref(bytes_valid))

        if err != AAC_DEC_OK:
            pos += chunk_size - bytes_valid.value if bytes_valid.value < len(chunk) else chunk_size
            continue

        # Decode frames until I need more data
        while True:
            err = fdk.aacDecoder_DecodeFrame(decoder, output_buffer, len(output_buffer), 0)

            if err == AAC_DEC_NOT_ENOUGH_BITS:
                # Need more data
                break
            elif err == AAC_DEC_OK:
                # Get stream info
                info = fdk.aacDecoder_GetStreamInfo(decoder)
                if info and info.contents.numChannels > 0:
                    num_channels = info.contents.numChannels
                    sample_rate = info.contents.sampleRate
                    frame_size = info.contents.frameSize

                    if frame_size > 0:
                        # Extract PCM - interleaved format
                        pcm_bytes = bytes(output_buffer[:num_channels * frame_size * 2])
                        all_pcm.append(pcm_bytes)
                        decoded_frames += 1
            elif err == AAC_DEC_TRANSPORT_SYNC_ERROR:
                # Sync error, skip some bytes
                error_count += 1
            else:
                error_count += 1
                break

        # Move forward by consumed bytes
        consumed = len(chunk) - bytes_valid.value
        pos += consumed if consumed > 0 else chunk_size

        if decoded_frames % 1000 == 0 and decoded_frames > 0:
            print(f"    Decoded {decoded_frames} frames, {num_channels} channels, {sample_rate} Hz")

    fdk.aacDecoder_Close(decoder)

    print(f"  Decoded: {decoded_frames} frames ({error_count} errors)")
    print(f"  Channels: {num_channels}, Sample rate: {sample_rate}")

    if not all_pcm:
        return None, 0, 0

    return b''.join(all_pcm), num_channels, sample_rate


def decode_stems(input_path: str, output_dir: str = None):
    """Decode a .stems file and split into individual stem WAV files."""

    input_path = Path(input_path)
    if output_dir is None:
        output_dir = input_path.parent / input_path.stem
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    stem_names = ['drums', 'bass', 'melody', 'vocals']

    print(f"Processing: {input_path.name}")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        adts_path = os.path.join(tmpdir, 'audio.aac')

        # Extract ADTS stream using ffmpeg
        print("\nStep 1: Extracting ADTS stream...")
        cmd = ['ffmpeg', '-y', '-i', str(input_path), '-c:a', 'copy', '-vn', adts_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if result.returncode != 0 or not os.path.exists(adts_path):
            print(f"Extraction failed: {result.stderr[-500:]}")
            return False

        # Decode with fdk-aac
        print("\nStep 2: Decoding with libfdk-aac...")
        pcm_data, num_channels, sample_rate = decode_adts_with_fdk(adts_path)

        if pcm_data is None:
            print("Decoding failed!")
            return False

        print(f"\nStep 3: Processing {len(pcm_data)} bytes of PCM data...")

        # Save full WAV
        full_wav = os.path.join(tmpdir, 'full.wav')
        with wave.open(full_wav, 'wb') as wav:
            wav.setnchannels(num_channels)
            wav.setsampwidth(2)  # 16-bit
            wav.setframerate(sample_rate)
            wav.writeframes(pcm_data)

        print(f"  Full WAV: {os.path.getsize(full_wav) / 1024 / 1024:.2f} MB")

        # Split into stems
        print("\nStep 4: Splitting into stems...")

        if num_channels < 8:
            print(f"  Warning: Only {num_channels} channels, expected 8")
            # Try splitting what I have
            for i in range(num_channels // 2):
                name = stem_names[i] if i < len(stem_names) else f'stem{i}'
                left = i * 2
                right = i * 2 + 1

                output_path = output_dir / f'{name}.wav'
                cmd = ['ffmpeg', '-y', '-i', full_wav,
                       '-af', f'pan=stereo|c0=c{left}|c1=c{right}',
                       str(output_path)]
                subprocess.run(cmd, capture_output=True)

                if output_path.exists():
                    print(f"  ✓ {name}.wav ({output_path.stat().st_size / 1024 / 1024:.2f} MB)")
        else:
            for i, name in enumerate(stem_names):
                left = i * 2
                right = i * 2 + 1

                output_path = output_dir / f'{name}.wav'
                cmd = ['ffmpeg', '-y', '-i', full_wav,
                       '-af', f'pan=stereo|c0=c{left}|c1=c{right}',
                       str(output_path)]
                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode == 0 and output_path.exists():
                    print(f"  ✓ {name}.wav ({output_path.stat().st_size / 1024 / 1024:.2f} MB)")
                else:
                    print(f"  ✗ {name}: Split failed")

    print(f"\nOutput: {output_dir}")
    return True


def main():
    if len(sys.argv) < 2:
        print("Engine DJ Stems Decoder (FDK-AAC ADTS)")
        print("=" * 50)
        print("\nUsage: python decode_fdk_adts.py <stems_file> [output_dir]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    success = decode_stems(input_file, output_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
