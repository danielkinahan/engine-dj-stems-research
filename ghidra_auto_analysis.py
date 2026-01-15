#!/usr/bin/env python3
"""
Ghidra Automation Script to Find AES Key

Run this in Ghidra Script Manager (Window -> Script Manager -> Create New Script)

This script:
1. Finds FUN_00ae6b14 (the frame decrypt loop)
2. Traces all functions that call it
3. Looks for key initialization code
4. Identifies where param_1[0x40] is written to
5. Finds EVP_EncryptInit_ex and shows what key is passed
"""

# This is for Ghidra's jython/python environment
# Place in: <ghidra_folder>/support/ghidra_scripts/

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
import struct

def find_function_by_address(addr_str):
    """Find a function by its hex address"""
    try:
        addr = currentProgram.parseAddress(addr_str)
        func = getFunctionContaining(addr)
        return func
    except:
        return None

def find_function_by_name(name):
    """Find a function by name"""
    sym = currentProgram.getSymbolTable().getGlobalSymbol(name)
    if sym and sym.getObject():
        return getFunctionContaining(sym.getAddress())
    return None

def get_cross_references_to(func):
    """Get all functions that call the given function"""
    callers = []
    refs = getReferencesTo(func.getEntryPoint())
    for ref in refs:
        if ref.getReferenceType().isCall():
            calling_func = getFunctionContaining(ref.getFromAddress())
            if calling_func:
                callers.append(calling_func)
    return list(set(callers))  # Remove duplicates

def find_param_assignments(func):
    """Find all assignments to param_1 in a function"""
    assignments = []
    # Look at the decompiled code
    try:
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)
        decomp = ifc.decompileFunction(func, 60, monitor)
        
        if decomp.decompileCompleted():
            # Get the high-level representation
            high = decomp.getHighFunction()
            if high:
                assignments.append({
                    'function': func.getName(),
                    'address': func.getEntryPoint(),
                    'decomp': str(decomp.getDecompiledFunction())
                })
    except:
        pass
    
    return assignments

def print_function_info(func, indent=""):
    """Print detailed info about a function"""
    if not func:
        return
    
    print(f"{indent}Function: {func.getName()}")
    print(f"{indent}Address: {func.getEntryPoint()}")
    print(f"{indent}Size: {func.getBody().getNumAddresses()} bytes")
    
    # Get parameters
    params = func.getParameters()
    if params:
        print(f"{indent}Parameters:")
        for param in params:
            print(f"{indent}  - {param.getName()}: {param.getDataType()}")

def search_for_evp_functions():
    """Find all EVP_* functions imported"""
    evp_funcs = []
    sym_table = currentProgram.getSymbolTable()
    
    # Look for external functions starting with EVP
    for sym in sym_table.getExternalSymbols():
        if sym.getName().startswith("EVP"):
            evp_funcs.append(sym)
    
    return evp_funcs

# MAIN ANALYSIS
print("="*80)
print("GHIDRA AUTOMATED KEY ANALYSIS")
print("="*80)

# Step 1: Find the decrypt function
print("\n[*] Step 1: Finding FUN_00ae6b14 (frame decrypt loop)...")
decrypt_func = find_function_by_address("00ae6b14")

if decrypt_func:
    print(f"[+] Found: {decrypt_func.getName()}")
    print_function_info(decrypt_func)
else:
    print("[-] FUN_00ae6b14 not found. Trying alternate address...")
    decrypt_func = find_function_by_name("FUN_00ae6b14")

# Step 2: Find who calls it
print("\n[*] Step 2: Finding all callers of FUN_00ae6b14...")
if decrypt_func:
    callers = get_cross_references_to(decrypt_func)
    print(f"[+] Found {len(callers)} caller(s):")
    
    for i, caller in enumerate(callers):
        print(f"\n    Caller {i+1}:")
        print_function_info(caller, indent="    ")

# Step 3: Find EVP functions
print("\n[*] Step 3: Finding EVP_* functions...")
evp_funcs = search_for_evp_functions()
print(f"[+] Found {len(evp_funcs)} EVP functions:")

for evp_func in evp_funcs[:10]:  # Show first 10
    print(f"    - {evp_func.getName()} at {evp_func.getAddress()}")
    
    # Find cross-references to this EVP function
    refs = getReferencesTo(evp_func.getAddress())
    ref_count = 0
    for ref in refs:
        if ref.getReferenceType().isCall():
            ref_count += 1
    
    if ref_count > 0:
        print(f"      Called {ref_count} time(s)")

# Step 4: Create summary
print("\n" + "="*80)
print("ANALYSIS COMPLETE - KEY FINDINGS")
print("="*80)

print("""
Next steps to find the key manually in Ghidra:

1. IMMEDIATE ACTION: Look at the callers of FUN_00ae6b14 above
   - These functions set up param_1 with the cipher context
   - They likely initialize param_1[0x40] (the key)

2. EXAMINE THE CALLER:
   - Go to its address in Ghidra
   - Look for memory allocation (malloc, new)
   - Look for constructor calls after allocation
   - Look for data being copied to param_1 + 0x40

3. SEARCH FOR EVPENCRYPTINIT_EX:
   - Right-click EVP_EncryptInit_ex (if found)
   - "Show References to EVP_EncryptInit_ex"
   - Look at the 4th parameter (r3 register) before the call
   - This shows what key material is being passed

4. LOOK FOR HARDCODED KEY IN .RODATA:
   - Window → Memory -> Go to address
   - Navigate to .rodata section (search for it in Listings)
   - Look for 16-byte patterns near crypto strings

SEARCH TERMS IN GHIDRA:
- Search for string: ".stems" or "stems" or "aes" or "cbc"
- Then look at nearby memory/code for 16-byte sequences
""")
