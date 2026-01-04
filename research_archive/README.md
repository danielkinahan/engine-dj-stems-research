# Decode Attempts

This folder contains various scripts that were tried during the reverse-engineering process. None of these successfully decode the stems files, but they document the approaches that were attempted.

## Analysis Scripts

- **analyze_stems.py** - Initial MP4 container analysis
- **analyze_adts.py** - Basic ADTS frame analysis  
- **analyze_adts_detail.py** - Detailed ADTS parsing with PCE elements
- **check_xor_encryption.py** - XOR encryption pattern analysis

## Decode Attempts

- **decode_stems.py** - Direct ffmpeg decode attempt
- **decode_pyav.py** - PyAV (Python FFmpeg bindings) attempt
- **decode_fdk.py** - libfdk-aac direct decoding attempt
- **decode_fdk_adts.py** - ADTS-wrapped fdk decoding
- **brute_force_decode.py** - Multiple ffmpeg options testing
- **frame_decode.py** - Frame-by-frame decode attempt

## Repair Attempts

- **fix_stems.py** - Attempt to fix MP4 headers
- **fix_adts.py** - ADTS header modification attempt
- **patch_mp4.py** - AudioSpecificConfig patching
- **recover_audio.py** - Chunk-based audio recovery

## Extraction

- **extract_stems.py** - Raw audio stream extraction

---

All scripts failed with channel element allocation errors because the AAC bitstream is encrypted/protected.
