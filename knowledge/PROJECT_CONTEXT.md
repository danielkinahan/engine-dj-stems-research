# Engine DJ .stems — Single Context File

**Last Updated:** January 4, 2026
**Purpose:** One-stop reference capturing everything that matters (status, evidence, codebase state, next steps). Use this instead of multiple docs.

---

## Executive Snapshot
- Goal: Decrypt and eventually create Engine DJ `.stems` files (8-ch AAC-LC stems).
- Status: Encryption algorithm unknown; all tested approaches fail. MP4 structure fully mapped. Keys are stored plaintext per frame but are not usable as XOR keys.
- Evidence: Frida found zero calls to OpenSSL, Windows CryptoAPI, or BCrypt → custom in-house encryption.
- Next move: Requires binary reverse engineering or memory capture from Engine DJ app; simple crypto guesses are exhausted.

---

## File Format (confirmed)
- Container: MP4
- Layout: `[ftyp 28B][free 8B][mdat hdr 8B][seed 4B][repeat frames][moov 71,122B]`
- Frame: 1648 bytes = 128B stored key-like block + 1520B encrypted audio block
- Seed: 0xe485b014 (same in both test files)
- Frames: 19,754 (file 1), 14,623 (file 2)
- Target audio (from moov): AAC-LC, 8 channels (4 stereo pairs), 44100 Hz, ~640 kbps, durations ~6:45 and ~4:58

---

## What Was Tried (all failed)
- XOR with repeating 128B blocks → valid MP4 container but AAC decoder errors ("Prediction not allowed", etc.), only ~0.05 s audio extractable.
- Stream-cipher style evolving keystream → same failure pattern.
- Raw data (no decryption), 128B-only, 1520B-only, whole 1648B frames, mixed alignments → all fail identically.
- Byte reordering/scrambling; alternative frame sizes (1536B, offsets); partial XOR (first 128B only); single key for all frames → all fail.
- LCG/PRNG or UUID-derived keys/seeds → no correlation; hundreds of parameter combos tried.
- Result across methods: 100-7,500 apparent AAC syncs, but spacing is random (1-47,828 bytes); real AAC would show consistent 300-1500 byte spacing. These are false positives.

---

## What We Know the 128B Blocks Are NOT
- Not XOR keys
- Not PRNG-derived (LCG, UUID, seed) keys
- Not plaintext AAC
- Likely encrypted per-frame headers, IVs, or integrity data (entropy ~98/128 unique bytes, not pure noise)

---

## Conclusion
- Encryption is proprietary and inline (no standard crypto libs observed). Further progress needs:
  1) Static RE of Engine DJ desktop binary to recover algorithm, or
  2) Dynamic capture of decrypted buffers/keys during playback/creation.
- Simple cryptanalytic guessing is a dead end.

---

## Codebase State (post-cleanup)
- Core library: `stems_lib.py` (single source for parsing, extraction, rebuild, test decrypt paths, analysis).
- Example usage: `decrypt_with_lib.py` (minimal workflow, still produces invalid audio as expected).
- Test harness: `CONSOLIDATED_TEST.py` (runs all approaches and shows failure).
- Key docs now condensed here; legacy multi-doc set kept for detail: `RESEARCH_SUMMARY.md`, `CONSOLIDATION_REPORT.md`, `CODE_ANALYSIS_SUMMARY.md`, `DECRYPTION_ATTEMPTS_SUMMARY.md`, `QUICK_START.md`.
- Test data: `stems/*.stems` + extracted `*.keys`.

---

## Firmware Analysis (controller, STM32F4)
- Firmware update packages (4.3.4 and 4.2.0) are multi-part XZ containers. Main payload extracted from 4.3.4:
  - Carve main XZ stream at offset 0x2C24, length 148,944,864 bytes → `MIXSTREAMPRO-4.3.4-main.xz`
  - Decompress to `MIXSTREAMPRO-4.3.4-main.bin` (512 MB)
- Vector tables: many found inside `MIXSTREAMPRO-4.3.4-main.bin` (e.g., offset 0x7409000: SP=0x20020000, Reset=0x0800C19D). Import base 0x08000000, language ARM:LE:32:Cortex (default compiler) in Ghidra.
- Packing layout: update file has ~65 concatenated XZ members; `find_vector_tables.py` and `firmware_scan_standalone.py` help locate payloads/constants.
- Quick scan of main.bin shows standard vectors and code; no MP4 strings yet (manual RE needed).

Recommended Ghidra workflow for firmware:
1) Import `MIXSTREAMPRO-4.3.4-main.bin` at base 0x08000000, ARM:LE:32:Cortex, default compiler; enable analysis.
2) Jump to a clean vector (e.g., 0x0800C19D from offset 0x7409000) and follow reset.
3) Hunt for frame-size constants (0x670, 0x5F0, 0x80) and crypto patterns (AES tables, stream ciphers, CRYP/RNG/CRC MMIO use).
4) Document findings in GHIDRA_ANALYSIS_GUIDE.md as you go.

Helper scripts:
- `firmware_scan_standalone.py`: scans blobs for constants/tokens.
- `find_vector_tables.py`: locates plausible vector tables in images.

Files produced:
- `MIXSTREAMPRO-4.3.4-main.xz`, `MIXSTREAMPRO-4.3.4-main.bin` (decompressed firmware)

---

## Minimal Commands to Reorient
- Run all tests: `python CONSOLIDATED_TEST.py`
- Extract keys: `python stems_lib.py stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems --extract-keys`
- Attempt XOR decrypt (for reference): `python decrypt_with_lib.py "stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems"`
- Inspect structure: `python stems_lib.py --info stems/1 0f7da717-a4c6-46be-994e-eca19516836c.stems`

---

## Practical Next Steps (ordered)
1) **Binary RE (high impact):** Disassemble Engine DJ desktop, locate stem encode/decode path, recover custom cipher.
2) **Dynamic capture:** Frida/WinDbg to hook playback or export, dump decrypted buffers, diff against encrypted frames.
3) **Automation fallback:** Use Engine DJ as a black box to generate stems (does not help decrypt existing files).
4) **Long shot:** Request SDK/format from Denon/Engine DJ.

---

## Success Criteria (to know you actually decrypted it)
- AAC sync words appear every ~300-1500 bytes consistently (not random sparse hits).
- FFmpeg/VLC decodes full duration with no AAC errors.
- All 8 channels audible and correctly separated.

---

## Quick Reminders
- All simple crypto guesses are exhausted; do not re-run XOR/PRNG ideas.
- Keys are stored plaintext per frame but are not the decryption key material.
- Container is valid MP4; encryption is at frame payload level.

---

## Contacts and Artifacts
- Primary library: stems_lib.py
- Example script: decrypt_with_lib.py
- Test runner: CONSOLIDATED_TEST.py
- Data: stems/ (two .stems files and extracted .keys)
- Detailed history (if needed): RESEARCH_SUMMARY.md, CONSOLIDATION_REPORT.md, CODE_ANALYSIS_SUMMARY.md, DECRYPTION_ATTEMPTS_SUMMARY.md, QUICK_START.md
