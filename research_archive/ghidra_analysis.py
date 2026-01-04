#!/usr/bin/env python3
"""
Ghidra Analysis Script for Engine DJ Binary
============================================

This script is designed to be run within Ghidra to analyze the Engine DJ binary
for encryption routines, AAC decoder initialization, and crypto library calls.

Usage: Place this in your Ghidra project and run via:
  - Window > Script Manager > Run Script
  - Or via Ghidra scripting API

It searches for:
  1. AAC decoder initialization (FDK-AAC library symbols)
  2. XOR operations in proximity to audio processing
  3. Crypto library imports and usage
  4. Audio frame processing loops
  5. Key derivation functions
"""

import re
from typing import List, Tuple

class EngineAnalyzer:
    """Ghidra-compatible analyzer for Engine DJ binary."""
    
    def __init__(self):
        self.findings = []
        self.functions_of_interest = []
    
    def search_patterns(self):
        """Search for encryption-related patterns in the binary."""
        
        patterns = {
            'fdk_aac_functions': [
                'aacDecoder_DecodeFrame',
                'aacDecoder_Open',
                'aacDecoder_Close',
                'aacDecoder_Fill',
                'aacDecoder_GetStreamInfo',
            ],
            'xor_operations': [
                r'xor\s+',  # XOR instruction
                r'lea.*xor',  # LEA with XOR
            ],
            'crypto_libs': [
                'libcrypto',
                'libssl',
                'OpenSSL',
                'mbedtls',
                'AES',
                'DES',
            ],
            'common_encryptions': [
                'EVP_',  # OpenSSL EVP functions
                'AES_encrypt',
                'AES_decrypt',
                'DES_ecb_encrypt',
            ]
        }
        
        return patterns
    
    def get_analysis_instructions(self) -> str:
        """Return detailed instructions for manual Ghidra analysis."""
        
        instructions = """
ENGINE DJ BINARY ANALYSIS GUIDE
===============================

GHIDRA SETUP:
1. Open Engine DJ binary in Ghidra
   - Windows: C:\\Program Files\\Engine DJ\\Engine DJ.exe
   - macOS: /Applications/Engine DJ/Engine DJ.app/Contents/MacOS/Engine DJ

2. Auto-analyze with default settings

3. Use the following search strategies:

SEARCH STRATEGY 1: FDK-AAC Library Symbols
-------------------------------------------
Window > Symbol Search, search for:
  - aacDecoder_DecodeFrame
  - aacDecoder_Open
  - aacDecoder_Fill
  
Cross-reference these functions:
  - Click "References" tab to find callers
  - Look for parameter setup (frame buffer, key, config)
  - Trace data flow backwards to find decryption code

SEARCH STRATEGY 2: XOR Operations
----------------------------------
Window > Search > For Strings

Search for patterns in disassembly:
  - Right-click any XOR instruction
  - Highlight all XOR instructions in function
  
Look for XOR patterns:
  - Near audio processing loops
  - In proximity to file read operations
  - With loop counters (suggests frame-by-frame XOR)

Edit > Find/Replace > In Listing
  - Search for instruction: "xor"
  - Check each result for audio/encryption context

SEARCH STRATEGY 3: Crypto Library Imports
------------------------------------------
Window > Symbol Tree
  - Expand "Imports" section
  - Look for OpenSSL, mbedtls, or custom crypto
  
Watch for:
  - EVP_CIPHER operations
  - Key derivation functions
  - HMAC operations
  - SHA/MD5 hash functions

SEARCH STRATEGY 4: String Searches
-----------------------------------
Window > Search > For Strings

Search for strings that might reveal:
  - "stem" or "Stem" or "STEM"
  - "decrypt" or "Decrypt"
  - "encrypt" or "Encrypt"
  - "key" or "Key" or "KEY"
  - "uuid" or "UUID"
  - Error messages related to audio

SEARCH STRATEGY 5: Audio Processing Entry Points
-------------------------------------------------
Look for main audio playback functions:
  - Search for "WASAPI" (Windows audio API)
  - Search for "Core Audio" or "AudioUnit" (macOS)
  - Cross-reference with stems file handling

Find the playback pipeline:
  1. File open/read
  2. MP4 parsing
  3. Audio frame extraction
  4. **DECRYPTION HAPPENS HERE**
  5. AAC decoder (fdk-aac)
  6. PCM output

SEARCH STRATEGY 6: Loop Analysis
---------------------------------
In likely audio processing functions:
  - Look for loops iterating over frames
  - Check loop body for XOR/crypto operations
  - Check if loop counter is used as XOR key input

ANALYSIS CHECKLIST
-------------------
[ ] Found all aacDecoder_* function calls
[ ] Identified caller context (stems vs regular MP4)
[ ] Found any XOR loops in audio path
[ ] Checked for OpenSSL/crypto imports
[ ] Traced parameter flow to decoder
[ ] Checked for per-frame vs global encryption
[ ] Found key derivation mechanism
[ ] Found where UUID/metadata might be used

KEY QUESTIONS TO ANSWER
------------------------
1. Is there ONE decryption key for whole file or MULTIPLE per-frame keys?
2. How is the key derived? (UUID, file hash, track ID, etc.)
3. What's the cipher? (Simple XOR, AES, ChaCha20, etc.)
4. Where is the key stored/fetched? (Database, embedded, computed)
5. Is decryption applied before or after AAC decoder expects it?

TIPS FOR GHIDRA ANALYSIS
------------------------
- Use "Decompile" (F2) to see pseudo-code of functions
- Right-click variables to see data flow graphs
- Use "Function Call Tree" view to see call hierarchy
- Set breakpoints in debugger and run Engine DJ with stems playing
- Use "High Level IL" option for clearer pseudo-code
- Follow cross-references (Ctrl+Shift+F) backwards to find keys
- Check all function parameters - one might be a key/IV

MEMORY-BASED VALIDATION
------------------------
After identifying the decryption code:
1. Run Engine DJ with stems playing
2. Use WinDbg/Frida to hook the decryption function
3. Log the inputs and outputs
4. Verify against your XOR hypothesis
"""
        
        return instructions

def write_analysis_guide(output_file: str):
    """Write analysis guide to file."""
    analyzer = EngineAnalyzer()
    
    with open(output_file, 'w') as f:
        f.write(analyzer.get_analysis_instructions())
    
    print(f"✓ Analysis guide written to: {output_file}")

if __name__ == "__main__":
    import os
    import sys
    
    output_path = "c:\\Users\\Daniel\\git\\engine-dj-stems-research\\GHIDRA_ANALYSIS_GUIDE.txt"
    write_analysis_guide(output_path)
    
    print("\nTo use in Ghidra:")
    print("1. Open Engine DJ.exe in Ghidra")
    print("2. Let it auto-analyze")
    print("3. Follow the analysis guide above")
    print("4. Document any findings in a new issue")
