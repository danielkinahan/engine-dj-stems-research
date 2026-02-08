# Ghidra + Frida Analysis Summary: Engine DJ.exe AES Key Capture

## What Ghidra Found (Static Binary Analysis - WINDOWS DESKTOP)

### Discovery: AES-128-CBC Cipher Confirmed

**Location:** Engine DJ.exe binary

**Key Functions Identified:**
1. **Function 0x14141d940** (`FUN_14141d940`)
   - Calls `av_aes_init` and `av_aes_crypt` from FFmpeg's avutil-56.dll
   - This is the stems frame encryption/decryption dispatcher

2. **Function 0x140214ea0** (`FUN_140214ea0`)
   - Initializes AES key from obfuscated bytes
   - Obfuscated bytes: `A5 D7 62 34 F6 52 EE FC 4C C9 34 88 DC 08 DB EB`
   - De-obfuscation: subtract 2 from each byte
   - Result: `A3 D5 60 32 F4 50 EC FA 4A C7 32 86 DA 06 D9 E9`

3. **FFmpeg AVUtil-56.dll Functions Called:**
   - `av_aes_alloc()` - allocate AES context
   - `av_aes_init(context, key, 128, mode)` - initialize with 128-bit AES
   - `av_aes_crypt(context, output, input, block_count, iv, mode)` - decrypt/encrypt

**Frame Structure:**
- 1648 bytes per frame
- 16-byte IV + 1520-byte encrypted AAC payload
- Mode: AES-128-CBC (per-frame IV)

## What's Wrong

**Problem:** The extracted key from the binary doesn't decrypt the .stems files.

The decrypted output has the same AAC sync marker density (~0.024%) as the raw encrypted data, indicating:
- The binary key is NOT the actual decryption key, OR
- The key is derived differently at runtime, OR  
- The key is loaded from memory/license/cloud at runtime

## Solution: Runtime Key Capture with Frida (REQUIRED NEXT STEP)

### Why Frida Works:
- **Ghidra is static** - shows what the code is *supposed* to do
- **Frida is dynamic** - shows what the code *actually does* at runtime with real data
- The key might be loaded/derived from licensing, UUID, cloud services, etc.

### New Frida Hook Available:

**File:** `hook_av_aes_runtime.py`

**What it does:**
1. Intercepts `av_aes_init` calls
2. Reads the actual 16-byte AES key being used
3. Logs it when stems files are opened/played
4. Captures the encryption mode (encrypt vs decrypt)

### Usage on Windows:

```bash
# Terminal 1: Run the Frida hook
python hook_av_aes_runtime.py

# Terminal 2: Start Engine DJ normally through GUI
# Then: Open a stems file (load for editing, playback, or export)

# Terminal 1: Will print captured key like:
# [+] av_aes_init called with 128-bit key:
#     Context: 0x...
#     Key: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
#     Mode: DECRYPT (1)
```

## Comparison: Binary Key vs Runtime

| Aspect | From Binary (0x140214ea0) | From Runtime (via Frida) |
|--------|---------------------------|--------------------------|
| Method | Extracted from code | Hooked during execution |
| Key   | `A3D56032F450ECFA4AC73286DA06D9E9` | UNKNOWN - must capture |
| Validity | Doesn't decrypt .stems | TBD |
| Reliability | Assumes hardcoded key | Captures actual key used |
| Security Level | Easy to find | Hidden from static analysis |

## Expected Outcomes

### Scenario 1: Key is hardcoded but obfuscated
- Frida will capture it → use for decryption ✅

### Scenario 2: Key is derived from UUID/metadata
- Frida will capture it → reveals derivation pattern
- May need to reverse-engineer key derivation function

### Scenario 3: Key is licensed/cloud-based
- Frida will show the actual key used
- Decryption may depend on license validity

## Implementation Priority

### ✅ Done
- Identified AES-128-CBC cipher (Ghidra static analysis)
- Located key initialization functions
- Confirmed FFmpeg library usage

### ⏳ Next (Runtime Capture)
1. Use Frida hook on running Engine DJ.exe
2. Open/play/export a stems file
3. Capture key from `av_aes_init` call
4. Test key against test .stems files
5. If valid → update all decryption scripts

### 🎯 Final (Full Automation)
1. Reverse-engineer key derivation if needed
2. Automate key extraction in Python
3. Decrypt all .stems files

## Why Binary Analysis Alone Isn't Enough

Your Frida research previously found **"NO OpenSSL or Windows crypto library calls"** - but you were looking for those specific libraries. **FFmpeg's avutil AES is different**, and it's embedded in the binary. The key behavior only manifests at runtime with real stems files.

---

**Next Action:** Run the Frida hook on a Windows machine with Engine DJ installed, then open a stems file to capture the real key.
