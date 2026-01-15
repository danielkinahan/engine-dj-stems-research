# Ghidra Analysis Guide: Finding the AES Key

## Current Status
- ✅ Algorithm: AES-128-CBC confirmed
- ✅ Key location: param_1[0x40] (offset 0x40 in cipher context)
- ✅ Key size: 16 bytes
- ✅ Decrypt call chain fully traced
- ❌ Key value: Unknown - need to find where it's SET

## The Problem
We know WHERE the key is used (FUN_00acdcec, FUN_00ae6b14) but not WHERE it's initialized.
The key must be written to param_1[0x40] BEFORE decryption starts.

## Step-by-Step Ghidra Analysis

### Step 1: Find Who Calls the Decrypt Functions
In Ghidra:
1. Navigate to `FUN_00ae6b14` (the frame loop function)
2. Right-click the function name → **References** → **Show References to FUN_00ae6b14**
3. Look at the **calling functions** (functions that CALL this one)
4. Identify the parent function that sets up param_1

**What to look for:**
- Functions that allocate memory (malloc, new, __cxa_allocate_exception)
- Functions that initialize structures
- Constructor-like patterns (initialization after allocation)

### Step 2: Search for Writes to Offset 0x40
In Ghidra:
1. **Search** → **Program Text...** → Search for: `[r0, #0x40]` or `[r1, #0x40]`
2. Or **Search** → **For Scalars** → Search for decimal: `64` (0x40 in hex)
3. Look for ARM store instructions like:
   - `str r2, [r0, #0x40]` (store register to offset 0x40)
   - `strb r3, [r1, #0x40]` (store byte)
   - `vstm` or `vst1` (NEON store)

**What to look for:**
- Functions that write 16 bytes starting at offset 0x40
- Loops that copy data to this location
- memcpy() calls with destination at param_1 + 0x40

### Step 3: Analyze the Dispatcher Function (UndefinedFunction_00ae7628)
This function has a state machine with different cases:
1. Open the function in Ghidra
2. Look for the **switch/case statement** or **if-else chain**
3. Find **case 2** (key setup) based on our notes
4. Trace what happens in that case

**In case 2, look for:**
- Calls to functions with "key", "init", "setup" in their names
- Vtable method calls at offset 0x90: `(*param_1->vtable[0x90])()`
- Any memcpy or data movement operations
- Constants being loaded (these could be the key!)

### Step 4: Look for EVP_EncryptInit_ex Calls
OpenSSL's EVP_EncryptInit_ex function signature:
```c
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, 
                       const EVP_CIPHER *type,
                       ENGINE *impl, 
                       const unsigned char *key,  // ← This is what we want!
                       const unsigned char *iv);
```

In Ghidra:
1. **Search** → **For Functions...** → "EVP_EncryptInit_ex"
2. Find all **cross-references** to this function
3. Look at the **4th parameter** (r3 register in ARM) - this is the KEY!
4. Trace back where r3 comes from before the call

**ARM calling convention:**
- r0 = ctx
- r1 = cipher type (EVP_aes_128_cbc)
- r2 = engine (usually NULL)
- r3 = key pointer ← **TRACE THIS!**
- [sp, #0] = iv pointer

### Step 5: Search for Constant Data Patterns
The key might be in a data section:

1. **Window** → **Defined Strings** → Look for encryption-related strings
2. Near those strings, look at the **data section**
3. **Search** → **Memory** → Search for 16-byte patterns:
   - High entropy sequences
   - Near .rodata section
   - Between string constants

**Technique: Look near error messages**
- Find strings like "invalid key" or "decryption failed"
- The key might be stored near these in memory

### Step 6: Trace the Cipher Context Object
The cipher context (param_1) is an object. Find its class:

1. Find where param_1 is **allocated** (malloc/new)
2. Look for the **constructor** called immediately after
3. In the constructor, find where member variables are initialized
4. Look specifically for initialization at **offset 0x40**

**Class structure hints:**
- Offset 0x00: vtable pointer
- Offset 0x40: key buffer (16 bytes) ← **Our target**
- Offset 0x80: another vtable/method pointer

### Step 7: Check for XOR Obfuscation
Keys are sometimes stored XOR'd with a constant:

In Ghidra, look for patterns like:
```c
for (i = 0; i < 16; i++) {
    key[i] = encrypted_key[i] ^ 0xAA; // or some constant
}
```

Or:
```c
key[0] = 0x12 ^ 0xFF;
key[1] = 0x34 ^ 0xFF;
// ... etc
```

### Step 8: Analyze Nearby Functions
Look at functions near FUN_00acdcec in the listing:

1. **Window** → **Functions** → Sort by address
2. Check functions within ±1000 addresses of 0x00acdcec
3. Look for initialization/setup functions
4. These might contain key material

## Practical Commands in Ghidra

### Find All References to a Register Offset
1. Select the line with `param_1[0x40]`
2. Right-click → **References** → **Find References to param_1**
3. Filter for **WRITE** operations

### Decompile to C
1. Select a function
2. Press **Ctrl+E** (or use **Window** → **Decompile**)
3. Look at the C code for clarity

### Cross-Reference Graph
1. Right-click function → **References** → **Show References to**
2. This shows all callers as a graph

## What to Bring Back

Once you find something interesting, export:

1. **Function address**: e.g., "Found key init at 0x00abc123"
2. **Assembly code**: Copy the relevant instructions
3. **Decompiled C**: Copy the C code from decompiler
4. **Constants**: Any 16-byte hex values you find
5. **Memory addresses**: Where data is loaded from

## Quick Wins to Try

### Quick Win #1: String Context
Search for ".stems" string, find where it's used, look at nearby code for key initialization.

### Quick Win #2: Test Hardcoded Values
Look in the .rodata section for 16-byte sequences that look like keys (not all zeros, not ARM code).

### Quick Win #3: Import Table
Check what crypto functions are imported:
- **Window** → **Symbol Table** → Filter for "EVP", "AES", "crypt"
- Look at cross-references to these imports

## Questions to Answer

1. **Where is param_1 allocated?** (Function address and caller)
2. **Is there a constructor?** (Function that runs after allocation)
3. **What writes to offset 0x40?** (Instruction address)
4. **Where does that data come from?** (Register, constant, function call)
5. **Are there any 16-byte constants in .rodata?** (Address and hex value)

## Expected Outcome

You should find one of:
- A hardcoded 16-byte constant in .rodata
- A function that computes/derives the key
- An XOR'd/encrypted key that needs transformation
- A reference to external data (less likely in offline system)

Let me know what you find at any step!
