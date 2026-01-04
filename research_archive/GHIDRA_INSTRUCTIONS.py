"""
Instructions for using Ghidra to find the encryption algorithm:

1. OPEN ENGINE DJ IN GHIDRA
   - Load: C:\Program Files\Engine DJ\Engine DJ.exe
   - Let Ghidra analyze it (takes a few minutes)

2. NAVIGATE TO KEY FUNCTIONS
   Once we get addresses from capture_aac_writes.py, you'll see something like:
   
   [0] Engine DJ.exe+0x41cee3
   [1] Engine DJ.exe+0x41d8dc
   [2] Engine DJ.exe+0x59836a
   
   In Ghidra:
   - Press 'G' (Go To)
   - Enter the address offset (e.g., 0x0041cee3)
   - Press OK

3. WHAT TO LOOK FOR IN THE DISASSEMBLY:
   
   XOR OPERATION (most likely):
   - XOR instruction: XOR reg, [memory]
   - Example: XOR EAX, [RBX+RCX]
   - Look for XOR in a loop
   
   LOOP PATTERN:
   ```assembly
   .loop:
       MOV AL, [RSI]        ; Load encrypted byte
       XOR AL, [RDI]        ; XOR with key byte
       MOV [RDX], AL        ; Store result
       INC RSI              ; Next byte
       INC RDI              ; Next key byte
       DEC RCX              ; Counter--
       JNZ .loop            ; Loop if not zero
   ```
   
   KEY GENERATION:
   - Look for function calls BEFORE the XOR loop
   - Common patterns:
     * Call to custom function with frame_index parameter
     * Memory read from a table (array of keys)
     * Hash function call (MD5, SHA256)
   
4. FIND THE KEY DERIVATION:
   
   Look for one of these patterns:
   
   a) SIMPLE TABLE LOOKUP:
      MOV RAX, [key_table + RCX*128]
      ; Where RCX = frame_index
   
   b) FUNCTION CALL:
      MOV RCX, frame_index
      CALL generate_key_function
      ; Result in RAX or written to buffer
   
   c) HASH-BASED:
      MOV RCX, uuid_ptr
      MOV RDX, frame_index
      CALL compute_hash
   
5. DECOMPILE THE FUNCTION:
   - Right-click on the function
   - Choose "Decompile"
   - Look at pseudo-C code
   - Search for:
     * Loop with XOR
     * Function calls with "key", "encrypt", "frame"
     * Array or buffer of size 128

6. SEARCH FOR STRINGS/REFERENCES:
   In Ghidra's "Defined Strings" window (Window → Defined Strings):
   - Search for: "stem", "key", "encrypt", "frame"
   - Double-click to see where it's used
   - Follow references

7. EXAMPLE OF WHAT YOU MIGHT FIND:
   ```c
   void encrypt_frame(uint8_t* input, uint8_t* output, int frame_index) {
       uint8_t key[128];
       
       // Key generation - THIS IS WHAT WE NEED
       generate_key_for_frame(key, frame_index);  // ← Find this function!
       
       // XOR operation
       for (int i = 0; i < input_size; i++) {
           output[i] = input[i] ^ key[i % 128];
       }
   }
   ```

8. ONCE YOU FIND generate_key_for_frame():
   - Decompile it
   - Look for the algorithm
   - Common patterns:
     * MD5(base_key + frame_index)
     * SHA256(UUID + frame_index)
     * Custom PRNG: seed = UUID; key = prng.next(frame_index)
   - Note any constants, magic numbers
   - Check for external library calls

9. REPORT BACK:
   When you find it, tell me:
   - The algorithm used (hash, PRNG, custom)
   - Any parameters (UUID, seed, frame_index)
   - Constants or magic numbers
   - The exact decompiled code

TIPS:
- Use Ghidra's cross-reference feature (Ctrl+Shift+F)
- Look for 128-byte buffer allocations
- Search for loops that iterate exactly 128 times
- Check for modulo 128 operations (% 128 or & 0x7F)
"""

print(__doc__)
