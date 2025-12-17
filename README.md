# Engine DJ Stems File Format Research

Reverse engineering research on Engine DJ Desktop's `.stems` file format.

## In short, the format is protected

**Engine DJ `.stems` files cannot be decoded with standard AAC decoders.** The audio data appears to be encrypted or uses a proprietary codec masquerading as AAC.

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

## Installation

```bash
git clone https://github.com/danielkinahan/engine-dj-stems-research.git
cd engine-dj-stems-research

# FFmpeg is required for analysis
# Ubuntu/Debian: sudo apt install ffmpeg
# macOS: brew install ffmpeg

```
### Optional: install pyav

`attempts/decode_pyav.py` requires the pyav package. Install this into a virtual-env or use your system package.

## Usage

Two stems files have been provided for conveniance in the `stems/` folder.

### Analyze a stems file

```bash
python analyze.py "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"
```

This will output:
- Container format details
- AudioSpecificConfig parsing
- PCE (Program Config Element) structure
- ADTS frame analysis
- XOR encryption pattern check

### Example Output

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

## Technical Details

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

## Future Research

I'm not sure what's next to check for. I've contacted Engine DJ support but haven't heard back.

- [ ] Reverse engineer Engine DJ Desktop binary?
- [ ] Analyze multiple stems files for encryption key patterns

## Contributing

If you have findings to share:
1. Open an issue with your analysis
2. Submit PRs with additional analysis tools
3. Share any progress on understanding the encryption

## Files

```
├── README.md           # This documentation
├── analyze.py          # Main analysis tool
├── requirements.txt    # Python dependencies (minimal)
├── LICENSE             # GPLv2 License
├── stems/              # Place .stems files here for analysis
└── attempts/           # Previous decode attempts (for reference)
```

## Disclaimer

This research is for educational purposes. The stems files are created by Engine DJ from music you own. This project aims to understand the format for interoperability purposes.

## License

GPLv2