#!/usr/bin/env python3
"""Find external stems processor files in Engine DJ installation."""

import os
import subprocess
import sys

# Common Engine DJ install locations
POSSIBLE_PATHS = [
    r"C:\Program Files\Inmusic\Engine Library",
    r"C:\Program Files (x86)\Inmusic\Engine Library",
    os.path.expanduser(r"~\AppData\Local\Programs\Engine Library"),
    os.path.expanduser(r"~\AppData\Local\Inmusic\Engine"),
]

print("Searching for Engine DJ installation folders...\n")

for base_path in POSSIBLE_PATHS:
    if not os.path.exists(base_path):
        print(f"❌ Not found: {base_path}")
        continue
    
    print(f"✅ Found: {base_path}\n")
    
    # Look for DLLs with "stems" in name
    print("  Stems-related DLLs:")
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if 'stems' in file.lower() and (file.endswith('.dll') or file.endswith('.exe')):
                full_path = os.path.join(root, file)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                print(f"    - {file} ({size_mb:.1f} MB) at {root}")
    
    # Look for processor/engine executables
    print("\n  Processor/Engine executables:")
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if any(x in file.lower() for x in ['processor', 'engine', 'stem', 'codec']):
                if file.endswith(('.dll', '.exe')):
                    full_path = os.path.join(root, file)
                    size_mb = os.path.getsize(full_path) / (1024 * 1024)
                    print(f"    - {file} ({size_mb:.1f} MB)")
    
    print("\n  All DLLs in main folder:")
    main_dlls = [f for f in os.listdir(base_path) if f.endswith('.dll')]
    for dll in sorted(main_dlls):
        full_path = os.path.join(base_path, dll)
        size_mb = os.path.getsize(full_path) / (1024 * 1024)
        print(f"    - {dll} ({size_mb:.1f} MB)")
    
    print("\n" + "="*70 + "\n")

print("Done!")
