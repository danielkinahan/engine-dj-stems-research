# Ghidra Analysis Guide - Key Generation Function

## Target Function
**Address**: `Engine DJ.exe + 0xb31196`  
**Purpose**: Generates 128-byte XOR keys for stems encryption  
**Characteristics**: Stateful, no external crypto calls

## Setup

1. **Open Ghidra** and create a new project
2. **Import**: `C:\Program Files\Engine DJ\Engine DJ.exe`
3. **Analyze**: Accept default analyzers, wait for completion
4. **Navigate to function**: Press 'G' and enter address `0xb31196` (relative to image base)

## What We Know

### Function Behavior
- **Called**: ~21,417 times per stems file (once per AAC frame)
- **Arguments** (same every time):
  - RCX (arg0): `0x210920c9f88` - Pointer to state structure
  - RDX (arg1): `0xfffffc00` (-1024) - Constant value
  - R8 (arg2): `0xc0b54ff1f8` - Stack pointer
  - R9 (arg3): `0x0` - Null

### Expected Output
- Generates 128-byte keys
- Keys are unique per call (frame-based state)
- No repeating pattern in keys

## Analysis Strategy

### Step 1: Identify State Structure
Look at what's accessed via RCX (arg0):
```
- Offsets being read/written
- Size of the structure
- Counter or index variables
- Seed or initialization values
```

### Step 2: Find the Core Algorithm
Look for:
- **XOR operations** (xor instruction)
- **Bit rotations** (rol, ror, shl, shr)
- **Multiplications** (imul, mul) - common in PRNGs
- **Additions** (add, lea) - used in LCG, XORshift
- **Loops** - for generating all 128 bytes

### Step 3: Trace Data Flow
- Where does the key data get written?
- Is it written to a buffer passed in args?
- Or returned via a pointer?
- How is state updated between calls?

## Common PRNG Patterns to Look For

### XORshift (Very Common)
```assembly
mov eax, [state]
mov ebx, eax
shl ebx, 13
xor eax, ebx
mov ebx, eax
shr ebx, 17
xor eax, ebx
mov ebx, eax
shl ebx, 5
xor eax, ebx
mov [state], eax
```

### Linear Congruential Generator (LCG)
```assembly
mov eax, [state]
imul eax, 1103515245  ; multiplier
add eax, 12345         ; increment
mov [state], eax
```

### Counter-based
```assembly
mov eax, [counter]
inc eax
mov [counter], eax
; Use counter to generate key bytes
```

## Validation

Once you identify the algorithm:

1. **Extract the constants**: multipliers, XOR values, shifts, etc.
2. **Implement in Python**
3. **Test**: Generate first key and compare with Key 1 from `keys_extracted.txt`

### Key 1 (for validation):
```
19 78 65 12 70 29 20 9f 4e a3 d2 27 df 52 b4 c8
... (128 bytes total in keys_extracted.txt)
```

## Tips

- **Right-click** on addresses → "Show References" to see where data is used
- **Create structure** (Ctrl+Shift+E) for the state object
- **Rename variables** (L key) to track purpose
- **Add comments** (; key) to document your findings
- **Use decompiler** (Window → Decompile) for high-level view

## Expected Timeline
- **Setup**: 15 min
- **Structure identification**: 30 min
- **Algorithm extraction**: 1-2 hours
- **Python implementation**: 30 min
- **Validation**: 15 min

**Total**: 3-4 hours

## Next Steps After Success

Once you have the key generator working:
1. Generate keys for any frame count
2. Encrypt your own 8-channel AAC audio
3. Package in MP4 container with proper boxes
4. Use in Engine DJ!
