#!/usr/bin/env python3
"""
Ghidra Script to Find the AES Key

Run this in Ghidra's Python console (Window -> Script Manager -> Create)

The key facts:
1. Key is at offset 0x40 in cipher context structure
2. Key is 16 bytes, used by AES-128-CBC
3. Key must be constant (works offline for any track)
4. Key is set BEFORE decrypt call chain

Strategy:
1. Search all function references to EVP_EncryptInit or EVP_EncryptInit_ex
2. For each reference, look at the arguments being passed
3. The second argument (key) should point to a 16-byte constant
4. Extract and test that constant

Alternative:
1. Find all 16-byte sequences in the binary
2. Test each one with test frames from stems files
3. Find which one works for ALL frames (not just frame 0)
"""

# For manual Ghidra use:
print("""
IN GHIDRA PYTHON CONSOLE:

from ghidra.program.model.address import AddressSet

# Search for EVP_aes_128_cbc symbol
print("Searching for EVP functions...")

# In Ghidra, you can:
currentProgram.getSymbolTable().getSymbols("EVP_EncryptInit_ex")

# Or use the search function tool
# Edit -> Search -> Program Text
# Search for "EVP"

# Then right-click each result and check cross-references
# Look for data references (not just code)
# Find what addresses are being loaded as parameters

# The key is likely a 16-byte global constant
# Look for initialization patterns like:
#   ldr r0, =0x<address>  (load address of 16 bytes)
#   bl EVP_EncryptInit_ex

# Alternative: In Ghidra, use Search -> For Strings
# Search in string tables for partial keys or related strings
""")

print("\n" + "="*80)
print("QUICKEST METHOD: Use Ghidra GUI")
print("="*80)
print("""
1. Open Engine_main_binary in Ghidra (already open)

2. Search for EVP functions:
   Search → For Strings... → "EVP_aes_128_cbc"
   Right-click result → Show References
   
3. Look at where this is called:
   The function calling EVP_aes_128_cbc likely sets up the key
   
4. Use Listing view to see the assembly:
   - Look for LDR R0, =<address> before EVP call
   - That address likely points to the key
   - Or look for MOV instructions loading key bytes
   
5. Navigate to suspected key address:
   Window → Address Table → Go to address
   View the 16 bytes at that location
   Test them with the Python decryption script
   
6. If found, test with test_found_key.py:
   key_hex = '<hexvalue>'
   # Run the test script
   
7. If THAT works on all frames, you've found it!
""")
