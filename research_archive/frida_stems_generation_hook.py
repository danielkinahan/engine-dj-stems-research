#!/usr/bin/env python3
"""
Frida Hook - Monitor Stems Generation in Engine DJ Desktop

This hooks the stems CREATION process to find where encryption happens.

Usage:
1. Start Engine DJ Desktop
2. Run: python frida_stems_generation_hook.py
3. In Engine DJ, analyze a track to generate stems
4. Watch console for function calls and data patterns
"""

import frida
import sys
import time
import json

FRIDA_SCRIPT = """
console.log("[*] Frida script loaded - Monitoring stems GENERATION");

// Hook file write operations (where encrypted data goes)
try {
    var WriteFile = Module.findExportByName("kernel32.dll", "WriteFile");
    Interceptor.attach(WriteFile, {
        onEnter: function(args) {
            this.size = args[2].toInt32();
            this.buffer = args[1];
            this.filename = null;
        },
        onLeave: function(retval) {
            if (this.size > 1000 && this.size < 100000000) {  // Likely audio data
                console.log("[WriteFile] Size: " + this.size + " bytes written");
            }
        }
    });
} catch (e) {
    console.log("[-] Could not hook WriteFile: " + e);
}

// Hook CreateFileW to track .stems file creation
try {
    var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    Interceptor.attach(CreateFileW, {
        onEnter: function(args) {
            var filename = args[0].readUtf16String();
            if (filename.toLowerCase().includes(".stems")) {
                console.log("[+] Creating stems file: " + filename);
                this.isStemsFile = true;
            } else if (filename.toLowerCase().includes(".mp4") ||
                       filename.toLowerCase().includes(".m4a")) {
                console.log("[+] Creating audio file: " + filename);
            }
        },
        onLeave: function(retval) {
            if (this.isStemsFile) {
                console.log("[+] Stems file handle: " + retval);
            }
        }
    });
} catch (e) {
    console.log("[-] Could not hook CreateFileW");
}

// Look for MP4/AAC related functions
console.log("[*] Searching for MP4/AAC encoder functions...");
var modules = Process.enumerateModules();

var audioModules = [];
modules.forEach(function(module) {
    try {
        var name = module.name.toLowerCase();
        if (name.includes("aac") || name.includes("fdk") || 
            name.includes("mp4") || name.includes("encoder") ||
            name.includes("codec") || name.includes("ffmpeg") ||
            name.includes("libav")) {
            console.log("[+] Audio/codec module: " + module.name + " at " + module.base);
            audioModules.push(module.name);
        }
    } catch (e) {}
});

// Hook potential stem generation functions
console.log("[*] Looking for stem separation/generation functions...");
modules.forEach(function(module) {
    try {
        if (module.name.toLowerCase().includes("engine")) {
            console.log("[+] Engine module: " + module.name);
            
            // Common stem generation function names to search for
            var stemFuncs = [
                "separate",
                "analyze",
                "stem",
                "split",
                "isolate",
                "drum",
                "bass",
                "vocal",
                "melody",
                "partition"
            ];
            
            try {
                module.enumerateExports().forEach(function(exp) {
                    var name = exp.name.toLowerCase();
                    stemFuncs.forEach(function(sfunc) {
                        if (name.includes(sfunc)) {
                            console.log("  [!] Function: " + exp.name + " at " + exp.address);
                            
                            // Hook this function
                            try {
                                Interceptor.attach(exp.address, {
                                    onEnter: function(args) {
                                        console.log("  [>>] " + exp.name + " called");
                                        console.log("       arg0: " + args[0]);
                                        console.log("       arg1: " + args[1]);
                                    },
                                    onLeave: function(retval) {
                                        console.log("  [<<] " + exp.name + " returned: " + retval);
                                    }
                                });
                            } catch (e) {}
                        }
                    });
                });
            } catch (e) {}
        }
    } catch (e) {}
});

// Hook memcpy/memmove (often used for frame processing)
try {
    var memcpy = Module.findExportByName("kernel32.dll", "memcpy") || 
                 Module.findExportByName("ntdll.dll", "memcpy") ||
                 Module.findExportByName("msvcrt.dll", "memcpy");
    if (memcpy) {
        console.log("[+] Hooked memcpy");
        // Don't actually hook - too noisy, but good to know it exists
    }
} catch (e) {}

// Look for XOR operations by hooking potential functions
console.log("[*] Searching for encryption-related exports in Engine modules...");
modules.forEach(function(mod) {
    if (mod.name.toLowerCase().includes("engine") || 
        mod.name.toLowerCase().includes("denon")) {
        try {
            mod.enumerateExports().forEach(function(exp) {
                var name = exp.name.toLowerCase();
                if (name.includes("encrypt") || name.includes("decrypt") ||
                    name.includes("cipher") || name.includes("xor") ||
                    name.includes("key") || name.includes("obfuscate")) {
                    console.log("[!!!] Crypto function found: " + exp.name + " at " + exp.address);
                    
                    // Hook it
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                console.log("[CRYPTO] " + exp.name + " called");
                                // Try to log first few bytes
                                try {
                                    var data = args[1].readByteArray(8);
                                    if (data) {
                                        console.log("  Data: " + hexdump(data, {length: 8}));
                                    }
                                } catch (e) {}
                            }
                        });
                    } catch (e) {}
                }
            });
        } catch (e) {}
    }
});

console.log("[*] Monitoring Engine DJ stem generation...");
console.log("[*] Start analyzing a track to generate stems NOW!");
"""

def on_message(message, data):
    """Handle Frida script messages"""
    if message['type'] == 'send':
        print(f"[Frida] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message}")
        if 'stack' in message:
            for line in message['stack'].split('\\n'):
                print(f"  {line}")

def main():
    print("=" * 80)
    print("Frida Hook - Engine DJ STEMS GENERATION Analysis")
    print("=" * 80)
    
    # Find and attach to Engine DJ
    try:
        print("\n[*] Attaching to Engine DJ.exe...")
        session = frida.attach("Engine DJ.exe")
        print("[+] Successfully attached!")
    except frida.ProcessNotFoundError:
        print("[-] Engine DJ.exe not running!")
        print("\n[!] Start Engine DJ Desktop first, then run this script again.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error attaching: {e}")
        sys.exit(1)
    
    # Load and run script
    try:
        script = session.create_script(FRIDA_SCRIPT)
        script.on('message', on_message)
        script.load()
        print("[+] Frida script loaded successfully!")
    except Exception as e:
        print(f"[-] Error loading script: {e}")
        sys.exit(1)
    
    # Instructions
    print("\n" + "=" * 80)
    print("📊 STEMS GENERATION MONITORING")
    print("=" * 80)
    print("""
KEY INSIGHT: We're hooking the CREATION process, not playback!

When you analyze a track in Engine DJ to generate stems:
1. Engine DJ reads the source audio
2. Applies stem separation algorithm
3. Encodes 8-channel AAC
4. APPLIES ENCRYPTION (XOR or cipher) ← This is what we want to find!
5. Writes .stems MP4 file

What to look for in the output:
─────────────────────────────────────

[+] Creating stems file: ...
  → This shows when a .stems file is being written

[WriteFile] Size: ...
  → This shows data being written (encrypted AAC frames?)

[+] Audio/codec module: ...
  → Shows which libraries handle encoding/encryption

[!] Function: ...
  → Stem separation or encoding functions

[!!!] Crypto function found: ...
  → BINGO! This is the encryption routine

[CRYPTO] ... called
  → Hook showing when encryption function is invoked

NEXT STEPS:
───────────
1. In Engine DJ, right-click on a track
2. Select "Analyze & Create Stems" (or similar)
3. Watch this console for output
4. Look for:
   - File creation timestamps
   - Function calls
   - Crypto functions being invoked
5. Note down any "Crypto function found" messages
6. Return to Ghidra with that function name/address

CRITICAL: If you see [!!!] Crypto function found:
────────────────────────────────────────────────
- Note the function name and address
- Go to Ghidra
- Search for that exact function name
- Analyze its implementation
- That's your decryption algorithm!
""")
    print("=" * 80)
    print("\n[*] Press Ctrl+C to stop monitoring...\n")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Stopping...")
        session.detach()
        print("[+] Detached from Engine DJ")

if __name__ == '__main__':
    main()
