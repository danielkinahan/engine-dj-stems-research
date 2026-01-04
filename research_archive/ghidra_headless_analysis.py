#!/usr/bin/env python3
"""
Ghidra Headless Analysis - Find Stems Encryption Algorithm

This script uses Ghidra's analyzeHeadless tool to:
1. Analyze Engine DJ.exe
2. Find functions related to stems
3. Identify encryption/decryption functions
4. Extract cross-references and call chains
"""

import subprocess
import os
import sys
import json
from pathlib import Path

GHIDRA_PATH = r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_12.0_PUBLIC"
ENGINE_DJ_PATH = r"C:\Program Files\Engine DJ\Engine DJ.exe"
PROJECT_DIR = r"C:\Users\Daniel\git\engine-dj-stems-research\ghidra_headless"
PROJECT_NAME = "EngineDJ_Analysis"

def run_ghidra_analysis():
    """Run headless Ghidra analysis on Engine DJ.exe"""
    
    print("=" * 80)
    print("Ghidra Headless Analysis - Engine DJ Stems")
    print("=" * 80)
    
    # Check if Ghidra exists
    if not os.path.exists(GHIDRA_PATH):
        print(f"❌ Ghidra not found at: {GHIDRA_PATH}")
        print("Install via: choco install ghidra")
        sys.exit(1)
    
    # Check if Engine DJ exists
    if not os.path.exists(ENGINE_DJ_PATH):
        print(f"❌ Engine DJ not found at: {ENGINE_DJ_PATH}")
        sys.exit(1)
    
    # Create project directory if it doesn't exist
    os.makedirs(PROJECT_DIR, exist_ok=True)
    
    print(f"\n[*] Ghidra: {GHIDRA_PATH}")
    print(f"[*] Binary: {ENGINE_DJ_PATH}")
    print(f"[*] Project: {PROJECT_DIR}/{PROJECT_NAME}")
    
    # Run analyzeHeadless (batch file on Windows)
    analyze_script = os.path.join(GHIDRA_PATH, "support", "analyzeHeadless.bat")
    
    if not os.path.exists(analyze_script):
        print(f"[-] analyzeHeadless.bat not found at: {analyze_script}")
        sys.exit(1)
    
    print(f"\n[*] Launching analyzeHeadless...")
    print(f"    Script: {analyze_script}")
    
    try:
        # Run analysis via cmd.exe (batch file)
        cmd = [
            "cmd.exe", "/c", analyze_script,
            PROJECT_DIR, PROJECT_NAME, 
            "-import", ENGINE_DJ_PATH, 
            "-overwrite"
        ]
        
        print(f"    Command: {' '.join(cmd)}\n")
        
        # Run analysis
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout for analysis
        )
        
        print("\n[*] Analysis output:")
        print(result.stdout)
        
        if result.stderr:
            print("\n[*] Warnings/Errors:")
            print(result.stderr)
        
        if result.returncode != 0:
            print(f"\n[!] Analysis returned code: {result.returncode}")
        else:
            print(f"\n[+] Analysis completed successfully!")
            print(f"[+] Project saved to: {PROJECT_DIR}/{PROJECT_NAME}")
            
            print("\n" + "=" * 80)
            print("NEXT STEPS:")
            print("=" * 80)
            print("""
1. Open the project in Ghidra GUI:
   Launch Ghidra → Recent Projects → EngineDJ_Stems
   
2. Once loaded, run our analysis script in Ghidra's Script Manager:
   Window → Script Manager → Create → New Script
   
3. Or, create a Ghidra Python script to analyze automatically
""")
        
    except subprocess.TimeoutExpired:
        print("[-] Analysis timed out (took > 5 minutes)")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


def create_ghidra_script():
    """Create a Ghidra Python script for analyzing stems"""
    
    script_content = '''# @author 
# @category Analysis
# @keybinding 
# @menupath Tools.Find Stems Encryption
# @toolbar 

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import CodeUnit

# Find all functions that might be related to stems
def find_stems_functions():
    print("[*] Searching for stems-related functions...")
    
    # Get the listing
    listing = currentProgram.getListing()
    
    # Search for relevant strings first
    search_strings = [
        "stem", "separate", "encrypt", "xor", "aac", "frame",
        "decrypt", "cipher", "key", "encode", "audio"
    ]
    
    matching_functions = set()
    
    for func in listing.getFunctions(True):
        func_name = func.getName().lower()
        for keyword in search_strings:
            if keyword in func_name:
                matching_functions.add(func)
                print(f"  [+] Found: {func.getName()} at {func.getEntryPoint()}")
    
    return matching_functions

# Find cross-references
def analyze_xrefs():
    print("[*] Analyzing cross-references...")
    
    # Look for common crypto function names
    crypto_funcs = ["aacDecoder_Open", "aacDecoder_Fill", "aacDecoder_DecodeFrame"]
    
    for func_name in crypto_funcs:
        try:
            # Find function by name
            func = getFunction(func_name)
            if func:
                print(f"  [+] Found: {func_name}")
                # Get xrefs to this function
                xrefs = list(getReferencesTo(func.getEntryPoint()))
                print(f"      References: {len(xrefs)}")
                for xref in xrefs[:5]:
                    print(f"        - From: {xref.getFromAddress()}")
        except:
            pass

# Main
print("=" * 60)
print("Engine DJ Stems Analysis Script")
print("=" * 60)

find_stems_functions()
analyze_xrefs()

print("\\n[+] Analysis complete!")
print("    Check the console output above for results")
'''
    
    script_path = os.path.join(PROJECT_DIR, "FindStemsEncryption.py")
    
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    print(f"\n[+] Created Ghidra script: {script_path}")
    print("    Use in Ghidra: Window → Script Manager → Run (FindStemsEncryption.py)")


if __name__ == '__main__':
    run_ghidra_analysis()
    create_ghidra_script()
