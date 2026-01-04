# Engine DJ Stems File Format Research

Reverse engineering research on Engine DJ Desktop's `.stems` file format/encryption.

## In short, the format is protected

**Engine DJ `.stems` files cannot be decoded with standard AAC decoders.** The audio data appears to be encrypted or uses a proprietary codec masquerading as AAC.

### Status: Partial Success ⚠️

**What Works:**
- ✅ Encryption mechanism fully understood (XOR cipher with 128-byte keys)
- ✅ 10 encryption keys successfully extracted
- ✅ First ~0.85 seconds of audio properly decrypted
- ✅ Proof-of-concept: 4 individual stems extracted (drums, bass, melody, vocals)

**What's Missing:**
- ❌ Only 10 of 21,417 keys extracted (99.95% still needed)
- ❌ Full-length playable stems (only 0.85s currently works)
- ❌ Key generation algorithm not yet reverse engineered

---

## Quick Start

### Prerequisites
```bash
pip install frida frida-tools
pip install pyav # Optional for attempts/decode_pyav.py
# FFmpeg and FFprobe in PATH
```

### Extract Working Stems (0.85 seconds)
```bash
python decrypt_proper_frames.py
python extract_working_stems.py
# Output: drums_working.wav, bass_working.wav, melody_working.wav, vocals_working.wav
```

### Decrypt First 10 Frames
```bash
python decrypt_proper_frames.py
# Output: stems_partial_1520frames.m4a
```

### Extract Individual Stems
```bash
# Drums (channels 0-1)
ffmpeg -i stems_partial_1520frames.m4a -t 0.85 \
  -af "pan=stereo|c0=c0|c1=c1" -c:a pcm_s16le drums.wav

# Bass (channels 2-3)
ffmpeg -i stems_partial_1520frames.m4a -t 0.85 \
  -af "pan=stereo|c0=c2|c1=c3" -c:a pcm_s16le bass.wav

# Melody (channels 4-5)
ffmpeg -i stems_partial_1520frames.m4a -t 0.85 \
  -af "pan=stereo|c0=c4|c1=c5" -c:a pcm_s16le melody.wav

# Vocals (channels 6-7)
ffmpeg -i stems_partial_1520frames.m4a -t 0.85 \
  -af "pan=stereo|c0=c6|c1=c7" -c:a pcm_s16le vocals.wav
```

### Verify Decryption
```bash
# Check file structure
ffprobe stems_partial_1520frames.m4a

# Test decoding
ffmpeg -v verbose -i stems_partial_1520frames.m4a \
  -t 5 -f null -
```

### Analyse existing stems

Two stems files have been provided for conveniance in the `stems/` folder.

```bash
python analyze.py "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
```

This will output:
- Container format details
- AudioSpecificConfig parsing
- PCE (Program Config Element) structure
- ADTS frame analysis
- XOR encryption pattern check

#### Example Output

```
Engine DJ Stems Analyzer
========================

Container: MP4/ISO Base Media
Audio: AAC-LC, 44100 Hz, 8 channels, 640 kbps

PCE Configuration:
  front[0]: CPE tag=0 (2ch)
  front[1]: SCE tag=0 (1ch)
  side[0]:  CPE tag=1 (2ch)
  back[0]:  CPE tag=2 (2ch)
  back[1]:  SCE tag=1 (1ch)
  Total: 8 channels

Frame Analysis:
  Frame 0: PCE (valid)
  Frame 1: CPE tag=12 (INVALID - not defined in PCE)
  Frame 2: CCE tag=0 (INVALID - CCE not defined)
  ...
```

---

## Overview

Engine DJ Desktop creates `.stems` files when analyzing tracks for stem separation. These files contain 4 separated audio stems (drums, bass, melody, vocals) in a proprietary format.

Unlike the standard [Native Instruments stem.mp4 format](https://www.native-instruments.com/en/specials/stems/) which uses 5 separate stereo AAC streams, Engine DJ uses a **single 8-channel AAC stream** with a Program Config Element (PCE) defining the channel layout.

## Format Summary

| Property | Value |
|----------|-------|
| Container | MP4/ISO Base Media (isom, iso2, mp41) |
| File Extension | `.stems` |
| Audio Codec | AAC-LC (allegedly) |
| Channels | 8 (4 stereo pairs) |
| Sample Rate | 44100 Hz |
| Bitrate | ~640 kbps |
| Channel Config | PCE-defined (channelConfiguration=0) |

### Channel Layout

| Channels | Stem |
|----------|------|
| 0-1 (L/R) | Drums |
| 2-3 (L/R) | Bass |
| 4-5 (L/R) | Melody |
| 6-7 (L/R) | Vocals |

## The Problem

The AAC bitstream is **fundamentally malformed** from a standard decoder's perspective:

1. **Frame 0** contains a valid PCE defining channel elements: CPE tag=0, SCE tag=0, CPE tag=1, CPE tag=2, SCE tag=1

2. **Subsequent frames** reference element tags that were never defined:
   - Frame 1: CPE instance_tag=12 ❌
   - Frame 4: CPE instance_tag=9 ❌
   - Various frames: CCE, LFE, DSE elements not in PCE ❌

3. **All standard decoders fail** with errors like:
   - `channel element X.Y is not allocated`
   - `Sample rate index in program config element does not match`
   - `Prediction is not allowed in AAC-LC`

### Tested Decoders

| Decoder | Result |
|---------|--------|
| FFmpeg (aac) | ❌ PCE/channel errors |
| FFmpeg (aac_fixed) | ❌ Same errors |
| faad2 | ❌ "Invalid number of channels" |
| GStreamer (faad) | ❌ "PCE shall be the first element" |
| GStreamer (fdkaacdec) | ❌ Negotiation failure |
| GStreamer (avdec_aac) | ❌ Channel count instability |
| libfdk-aac (direct) | ❌ Configuration errors |
| PyAV | ❌ Same as FFmpeg |

### Encryption Analysis

XOR encryption analysis was performed:
- XOR 0x19 on Frame 1's first byte produces valid `CPE tag=0`
- However, each frame requires a different XOR value with no discernible pattern
- Not simple XOR with: frame index, offset, length, or file UUID

Required XOR values show no pattern:
```
Frame  1: 0x19    Frame  6: 0x29    Frame 11: 0xd2
Frame  2: 0x78    Frame  7: 0x20    Frame 12: 0x27
Frame  3: 0x65    Frame  8: 0x9f    Frame 13: 0xdf
Frame  4: 0x12    Frame  9: 0x4e    Frame 14: 0x52
Frame  5: 0x70    Frame 10: 0xa3    Frame 15: 0xb4
```

## Understanding the Encryption

### File Structure
Engine DJ .stems files are **encrypted MP4 containers** with 8-channel AAC-LC audio:

```
.stems file (MP4 container)
├── ftyp (file type) - UNENCRYPTED
├── free (padding) - UNENCRYPTED  
├── mdat (media data) - ENCRYPTED ← XOR cipher applied here
└── moov (metadata) - UNENCRYPTED
```

**Audio Format:**
- Codec: AAC-LC (Advanced Audio Coding)
- Sample Rate: 44,100 Hz
- Channels: 8 (4 stereo pairs)
- Bitrate: 641 kbps
- Channel mapping:
  - Ch 0-1: Drums (stereo)
  - Ch 2-3: Bass (stereo)
  - Ch 4-5: Melody (stereo)
  - Ch 6-7: Vocals (stereo)

### Encryption Details

**Cipher:** XOR (bitwise exclusive-or)
- Simple but effective obfuscation
- Symmetric: encryption = decryption with same key

**Key Structure:**
- Size: 128 bytes per key
- Application: One unique key per AAC frame (1520 bytes/frame)
- Total frames: 21,417 frames in sample file (~405 seconds)
- Keys extracted: 10 (frames 1-10)
- **Keys needed:** 21,417 keys for full decryption

**Key Characteristics:**
- ✅ NOT hardcoded in binary (searched, not found)
- ✅ NOT file-specific (same key works across files)
- ✅ NOT stream cipher (99-100% byte variation between keys)
- ❌ NOT from standard hash functions (MD5/SHA256 tested, no match)
- ❓ Likely: Custom KDF, PRNG with UUID seed, or proprietary algorithm

**Decryption Formula:**
```
For each AAC frame (1520 bytes):
  plaintext_byte = encrypted_byte XOR key_byte[position % 128]
```

---

## How Keys Were Extracted

### Method: Frida Runtime Hooking

1. **Hooked `avcodec_receive_packet`** (FFmpeg)
   - Captured unencrypted AAC packets from encoder
   
2. **Hooked `WriteFile`** (Windows API)
   - Captured encrypted data being written to disk

3. **XOR Comparison**
   - `unencrypted XOR encrypted = key`
   - Extracted 128-byte keys for first 10 frames

4. **Validation**
   - Tested extracted keys on 2 different .stems files
   - Both produced valid FFmpeg signature (`Lavc58.134.10`)

### Frida Script
See [`hook_packet_data.py`](hook_packet_data.py) - captures first 10 packets

### Running the Frida Capture

**Prerequisites:**
```bash
pip install frida frida-tools
```

**Steps:**

1. **Launch Engine DJ Desktop** (but don't generate stems yet)

2. **Attach Frida** in a terminal:
   ```bash
   frida -l hook_packet_data.py -n "Engine DJ.exe"
   ```

3. **Generate stems** in Engine DJ Desktop:
   - Right-click track → "Generate Stems"
   - Wait for processing to complete

4. **View output** in Frida terminal:
   - Shows hex dumps of each packet + WriteFile call
   - Currently captures first 10 packets

5. **Extract keys** from captured output:
   ```bash
   # Copy hex output to packets_hex.txt
   python extract_keys_from_packets.py
   # Output: keys_extracted.txt
   ```

**To capture ALL keys (recommended for full solution):**
- Edit `hook_packet_data.py` line 42:
  ```python
  if packetCount >= 10: return;  # Change 10 to 25000
  ```

---

## Current Limitations

### The Problem

```
File contains:     21,417 AAC frames (1520 bytes each)
Keys extracted:    10 keys
Keys needed:       21,417 keys
Missing:           21,407 keys (99.95%)
```

**Result:** Only first 10 frames (~0.85 seconds) decrypt correctly. After frame 10, AAC decoder encounters encrypted data and fails with:
- "Reserved bit set"
- "Number of bands exceeds limit"
- "Prediction is not allowed in AAC-LC"

### Why Simple Key Repetition Fails

Attempting to repeat the 10 keys cyclically causes AAC bitstream errors because each frame requires its **own unique key**. The keys are not generated through simple patterns.

---

## Key Extraction Tools

The repository contains several essential Python scripts:

### `hook_packet_data.py`
- **Purpose:** Frida script for runtime key extraction
- **Method:** Hooks FFmpeg's `avcodec_receive_packet` and Windows `WriteFile`
- **Output:** Hex dumps of unencrypted packets + encrypted writes
- **Current:** Captures first 10 packets (modify to capture all 21,417)
- **Usage:** `frida -l hook_packet_data.py -n "Engine DJ.exe"`

### `extract_xor_key.py`
- **Purpose:** Original breakthrough - single key extraction
- **Method:** XORs unencrypted packet with encrypted WriteFile data
- **Output:** Single 128-byte key
- **Validation:** Tested on 2 different .stems files successfully

### `extract_keys_from_packets.py`
- **Purpose:** Batch key extraction from captured Frida output
- **Input:** `packets_hex.txt` (manually copied from Frida terminal)
- **Output:** All keys to `keys_extracted.txt`
- **Status:** Successfully extracted all 10 captured keys

### `decrypt_proper_frames.py` ⭐ WORKING SOLUTION
- **Purpose:** Main decryption script using frame-based key application
- **Method:** Applies one 128-byte key per 1,520-byte AAC frame
- **Output:** `stems_partial_1520frames.m4a`
- **Status:** Successfully decrypts first 10 frames (~0.85 seconds)
- **Validation:** FFmpeg test passed - "First 5 seconds decoded successfully"

### `extract_working_stems.py`
- **Purpose:** Split 8-channel audio into 4 stereo WAV files
- **Method:** Uses FFmpeg pan filter on each channel pair
- **Output:** drums_working.wav, bass_working.wav, melody_working.wav, vocals_working.wav
- **Status:** Produces playable audio (currently 0.85 seconds each)

---

## Usage Examples

### Test Decryption with FFmpeg
```bash
# Verbose decoding test (first 5 seconds)
ffmpeg -v verbose -i stems_partial_1520frames.m4a -t 5 -f null -

# Expected output:
# "Input #0, mov,mp4,m4a..."
# "Stream #0:0(und): Audio: aac (LC)..."
# "frame= 217 fps=0.0 q=-0.0 Lsize=N/A time=00:00:05.01..."
```

### Check File Properties
```bash
# Detailed file analysis
ffprobe -v error -show_format -show_streams stems_partial_1520frames.m4a

# Quick info
ffprobe stems_partial_1520frames.m4a
```

### Extract Specific Duration
```bash
# Extract only the working 0.85 seconds
ffmpeg -i stems_partial_1520frames.m4a -t 0.85 \
  -af "pan=stereo|c0=c0|c1=c1" \
  -c:a pcm_s16le drums_0.85s.wav
```

### Verify Audio Playback
```bash
# Play in FFplay (if available)
ffplay -t 0.85 stems_partial_1520frames.m4a

# Or extract and play WAV
python extract_working_stems.py
# Then open drums_working.wav in any media player
```

### Check Extracted Keys
```bash
# View first key
head -n 5 keys_extracted.txt

# Count total keys
findstr /R "^Key" keys_extracted.txt | find /C "Key"
# Should show: 10
```

---

## Technical Details

### Memory Locations (Engine DJ.exe)

Functions involved in encryption:
- `+0xb31196` - Called per frame, likely key generation
- `+0xb2e6df` - Follows in call stack, handles WriteFile

Libraries loaded:
- `avcodec-58.dll` - FFmpeg audio encoder
- `bcrypt.dll` - Windows CNG (NOT used for stems encryption)
- `libcrypto-1_1-x64.dll` - OpenSSL (purpose unclear)

### AAC Frame Structure

Each AAC frame in the .stems file:
- Size: 1520 bytes (fixed)
- Contains: 1024 audio samples
- Duration: ~23ms per frame (at 44.1kHz)
- Frames per second: ~43 frames/sec

### MP4 Box Layout

```
Offset    Size        Type    Encrypted?
0x000000  28 bytes    ftyp    No
0x00001C  8 bytes     free    No
0x000024  32,555,032  mdat    YES ← Encrypted payload starts at 0x2C
0x1F0C03C 71,122      moov    No
```


### AudioSpecificConfig

```
Hex: 1200050848002008c8200e4c61766335382e3133342e31303056e500

audioObjectType: 2 (AAC-LC)
samplingFrequencyIndex: 4 (44100 Hz)
channelConfiguration: 0 (PCE follows)
```

### Program Config Element

The PCE in the ASC defines 8 channels using front/side/back elements:
- 2 front channel elements (CPE + SCE = 3 channels)
- 1 side channel element (CPE = 2 channels)  
- 2 back channel elements (CPE + SCE = 3 channels)

### ADTS Frame Structure

Each frame has:
- 7-byte ADTS header (sync, profile, sample rate, channel config=0)
- Raw data block starting with syntactic elements

The problem is that raw data blocks reference undefined element tags.

## Comparison with Standard Stem Format

| Feature | Engine DJ (.stems) | NI Stem (.stem.mp4) |
|---------|-------------------|---------------------|
| Audio streams | 1 × 8-channel | 5 × stereo |
| Codec | AAC (protected?) | AAC or ALAC |
| Channel config | PCE-based | Standard stereo |
| Decoder compat | ❌ Proprietary | ✅ Standard |
| Metadata | Minimal | Rich (JSON) |

## Possible Explanations

1. **Stream Cipher Encryption** - Audio data encrypted with a key derived from file metadata or Engine DJ account
2. **Proprietary Codec** - Not actually AAC, just using AAC headers for container compatibility
3. **Modified Decoder** - Engine DJ uses a custom AAC decoder with non-standard element mapping
4. **DRM Protection** - Intentional obfuscation to prevent extraction



## Contributing

If you have findings to share:
1. Open an issue with your analysis
2. Submit PRs with additional analysis tools
3. Share any progress on understanding the encryption

## Disclaimer

This research is for educational purposes. The stems files are created by Engine DJ from music you own. This project aims to understand the format for interoperability purposes.

## License

GPLv2