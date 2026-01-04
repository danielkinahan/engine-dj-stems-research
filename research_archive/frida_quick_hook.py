#!/usr/bin/env python3
"""
Quick Frida Hook - Find AAC Decoder and File I/O

Usage:
1. Start Engine DJ Desktop
2. Run: python frida_quick_hook.py
3. Play a stems track in Engine DJ
4. Watch output for function calls
"""

import frida
import sys
import time

FRIDA_SCRIPT = """
console.log("[*] Frida hooks installed - monitoring Engine DJ");

// Import modules
var kernel32 = Module.getBaseAddress("kernel32.dll");

// Hook ReadFile to see file access
try {
    var ReadFile = Module.findExportByName("kernel32.dll", "ReadFile");
    Interceptor.attach(ReadFile, {
        onEnter: function(args) {
            this.filename = null;
            this.size = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.size > 0 && this.size < 100000000) {  // Reasonable size
                console.log("[ReadFile] Size: " + this.size + " bytes");
            }
        }
    });
} catch (e) {}

// Hook CreateFileW to identify file being opened
try {
    var CreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
    Interceptor.attach(CreateFileW, {
        onEnter: function(args) {
            var filename = args[0].readUtf16String();
            if (filename.toLowerCase().includes(".stems") || 
                filename.toLowerCase().includes(".mp4")) {
                console.log("[+] File opened: " + filename);
            }
        }
    });
} catch (e) {}

// Look for any function with "aac" in the name
console.log("[*] Searching for AAC decoder functions...");
var modules = Process.enumerateModules();
modules.forEach(function(module) {
    try {
        if (module.name.toLowerCase().includes("fdk") || 
            module.name.toLowerCase().includes("aac") ||
            module.name.toLowerCase().includes("avcodec")) {
            console.log("[+] Audio module found: " + module.name + " at " + module.base);
            
            // Try to hook common aac functions
            var funcs = [
                "aacDecoder_Open",
                "aacDecoder_Close", 
                "aacDecoder_Fill",
                "aacDecoder_DecodeFrame",
                "aacDecoder_ConfigRaw"
            ];
            
            funcs.forEach(function(fname) {
                try {
                    var func = Module.findExportByName(module.name, fname);
                    console.log("  [!] Found export: " + fname);
                    Interceptor.attach(func, {
                        onEnter: function(args) {
                            console.log("[AAC] " + fname + " called");
                            console.log("  arg0: " + args[0]);
                            console.log("  arg1: " + args[1]);
                        }
                    });
                } catch (e) {}
            });
        }
    } catch (e) {}
});

// Hook common XOR patterns
console.log("[*] Hooking memory writes for potential decryption...");
var ranges = Process.enumerateRanges("r--");
console.log("[*] " + ranges.length + " readable memory ranges");

// Try to find xor operations by hooking potential cipher functions
try {
    // Look for functions with specific names
    var possibleCipherFuncs = ["decrypt", "decipher", "cipher", "xor", "transform"];
    
    Process.enumerateModules().forEach(function(mod) {
        if (mod.name.toLowerCase().includes("engine")) {
            try {
                mod.enumerateExports().forEach(function(exp) {
                    var name = exp.name.toLowerCase();
                    possibleCipherFuncs.forEach(function(cfunc) {
                        if (name.includes(cfunc)) {
                            console.log("[!] Suspicious function: " + exp.name + " at " + exp.address);
                        }
                    });
                });
            } catch (e) {}
        }
    });
} catch (e) {}

console.log("[*] Monitoring Engine DJ... Load a stems file now!");
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
    print("Frida Quick Hook - Engine DJ Stems Analysis")
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
    print("🎯 Next Steps:")
    print("=" * 80)
    print("""
1. In Engine DJ:
   - Open a stems file in the browser
   - Click it to load into a deck
   - Press Play

2. Watch this console for output showing:
   - [ReadFile] - File I/O operations
   - [+] File opened - .stems access
   - [+] Audio module found - Decoder libraries
   - [!] Found export - AAC decoder functions
   - [!] Suspicious function - Encryption functions

3. Look for patterns:
   - Which AAC functions are called?
   - In what order?
   - What happens before/after decoding?

4. Key findings to note:
   - Any "decrypt" or "xor" function names
   - The call sequence to aacDecoder functions
   - Any custom function names related to stems

5. Once you identify key functions:
   - Go back to Ghidra
   - Search for those function names
   - Analyze their implementation
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
