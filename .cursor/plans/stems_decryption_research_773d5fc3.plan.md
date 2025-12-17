---
name: Stems Decryption Research
overview: ""
todos:
  - id: binary-analysis
    content: Analyze Engine DJ binary to find decryption routines
    status: pending
  - id: cross-file-analysis
    content: Create script to compare byte patterns across multiple stems files
    status: pending
  - id: database-analysis
    content: Examine Engine DJ database for encryption-related metadata
    status: pending
  - id: memory-intercept
    content: Set up memory/audio API interception during playback
    status: pending
  - id: custom-decoder
    content: Explore modified AAC decoder that bypasses element validation
    status: pending
---

# Engine DJ Stems Decryption Research Plan

## Current State Summary

The research so far has established:

- `.stems` files are MP4 containers with 8-channel AAC audio (4 stereo pairs for drums/bass/melody/vocals)
- **Frame 0** is valid and contains a proper PCE (Program Config Element)
- **Subsequent frames** have invalid element tags that don't match the PCE definition
- XOR analysis shows each frame needs a different XOR value with no discernible pattern
- All standard decoders (FFmpeg, faad2, GStreamer, libfdk-aac) fail

## Potential Research Avenues

### 1. Binary Analysis of Engine DJ Desktop Application (Highest Potential)

The most promising approach is reverse engineering the Engine DJ Desktop binary to find the decryption routine.

**Why this works:**

- Engine DJ *must* contain the decryption key or algorithm to play these files
- The encryption appears to be a stream cipher operating on raw AAC data

**Approach:**

- Use disassembly tools (Ghidra, IDA Pro, Hopper) on the Engine DJ binary
- Search for AAC decoder initialization code
- Look for XOR operations or crypto library calls near audio decoding
- Find references to FDK-AAC or similar AAC codec libraries and trace the data flow

**Files/locations to target:**

- macOS: `/Applications/Engine DJ/Engine DJ.app/Contents/MacOS/Engine DJ`
- Windows: `C:\Program Files\Engine DJ\Engine DJ.exe`

---

### 2. Cross-File Pattern Analysis

Compare multiple `.stems` files to identify encryption key derivation.

**Observations from current files:**

- Both files share the same UUID suffix (`0f7da717-a4c6-46be-994e-eca19516836c`)
- Both files start with identical bytes in the mdat atom header region (`e485 b014 117a e53b...`)
- Frame 0 (PCE) appears valid in both files

**Research questions:**

- Does the UUID relate to the encryption key?
- Is there a per-file key stored elsewhere (Engine DJ database, cloud sync)?
- Are there common encrypted patterns across files from the same source?

**Script to create:** Compare byte patterns across stem files at key offsets

---

### 3. Memory Dump Analysis During Playback

Capture decrypted audio data while Engine DJ is playing.

**Approach:**

- Run Engine DJ with stems playing
- Use memory analysis tools to find the decrypted AAC frames or PCM audio
- Intercept audio API calls (Core Audio on macOS, WASAPI on Windows)
- Use Frida to hook into decryption functions

**Note:** This produces the audio but doesn't reveal the algorithm

---

### 4. Network/API Analysis

Check if Engine DJ fetches decryption keys from a server.

**Approach:**

- Use Wireshark/mitmproxy while Engine DJ initializes stems
- Check for API calls to Denon/inMusic servers
- Analyze any token/license verification

---

### 5. Alternative Decoding Strategies

Try non-standard AAC decoding approaches that might tolerate the "invalid" element tags.

**Ideas:**

- Write a custom AAC parser that ignores PCE validation
- Modify FFmpeg source to bypass element tag checking
- Test if the element tags follow a remapped pattern (e.g., `tag XOR constant = valid_tag`)
- Analyze if all frames use the same tag mapping (suggesting simple remapping vs encryption)

---

### 6. Engine DJ Database Analysis

Check if decryption metadata is stored in Engine DJ's local database.

**Locations:**

- macOS: `~/Music/Engine Library/Database2/`
- Windows: `Documents\Engine Library\Database2\`

**Look for:**

- Tables referencing stems files
- Stored keys, salts, or metadata
- Relationships between track IDs and encryption parameters

---

## Recommended Starting Point

I recommend starting with **Avenue 1 (Binary Analysis)** combined with **Avenue 6 (Database Analysis)** because:

1. The encryption key must exist somewhere Engine DJ can access it
2. Binary analysis will reveal the exact algorithm used
3. Database analysis might reveal per-track encryption metadata

Would you like me to help create analysis scripts for any of these avenues?