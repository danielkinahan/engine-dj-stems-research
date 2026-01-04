#!/usr/bin/env python3
"""
Simplified Frida Hook - Monitor Stems Generation

Focus on finding stem-related and crypto functions
"""

import frida
import sys
import time

FRIDA_SCRIPT = """
console.log("[*] Simplified Frida hook for stems generation");

// Search all modules for stem/crypto functions
console.log("[*] Scanning for stem separation and crypto functions...");

var foundFunctions = {
    stem: [],
    crypto: [],
    codec: [],
    audio: []
};

Process.enumerateModules().forEach(function(module) {
    try {
        // Skip system libraries for cleanliness
        var modName = module.name.toLowerCase();
        if (modName.includes("system32") || modName.includes("syswow64")) {
            return;
        }
        
        // Look for engine/denon specific modules
        if (modName.includes("engine") || modName.includes("denon") || 
            modName.includes("aac") || modName.includes("fdk") ||
            modName.includes("separator") || modName.includes("stems")) {
            console.log("[+] Interesting module: " + module.name + " at " + module.base);
        }
        
        // Try to enumerate exports
        try {
            module.enumerateExports().forEach(function(exp) {
                var name = exp.name.toLowerCase();
                
                // Check for stem-related functions
                if (name.includes("stem") || name.includes("separate") || 
                    name.includes("isolate") || name.includes("drum") ||
                    name.includes("bass") || name.includes("vocal")) {
                    foundFunctions.stem.push({
                        name: exp.name,
                        module: module.name,
                        address: exp.address
                    });
                    console.log("[STEM] " + module.name + "::" + exp.name);
                }
                
                // Check for crypto functions  
                if (name.includes("encrypt") || name.includes("decrypt") ||
                    name.includes("cipher") || name.includes("xor") ||
                    name.includes("obfuscat") || name.includes("crypt")) {
                    foundFunctions.crypto.push({
                        name: exp.name,
                        module: module.name,
                        address: exp.address
                    });
                    console.log("[CRYPTO!!!] " + module.name + "::" + exp.name);
                }
                
                // Check for codec functions
                if (name.includes("aac") || name.includes("encode") ||
                    name.includes("decoder") || name.includes("encoder")) {
                    foundFunctions.codec.push({
                        name: exp.name,
                        module: module.name,
                        address: exp.address
                    });
                    console.log("[CODEC] " + module.name + "::" + exp.name);
                }
                
                // Check for audio functions
                if (name.includes("audio") || name.includes("frame") ||
                    name.includes("sample") || name.includes("pcm")) {
                    foundFunctions.audio.push({
                        name: exp.name,
                        module: module.name,
                        address: exp.address
                    });
                }
            });
        } catch (e) {
            // Module doesn't have exports or can't enumerate
        }
    } catch (e) {
        // Skip this module
    }
});

console.log("[*] ===================== SUMMARY =====================");
console.log("[*] Stem functions found: " + foundFunctions.stem.length);
console.log("[*] Crypto functions found: " + foundFunctions.crypto.length);
console.log("[*] Codec functions found: " + foundFunctions.codec.length);
console.log("[*] Audio functions found: " + foundFunctions.audio.length);
console.log("[*] ====================================================");

if (foundFunctions.crypto.length > 0) {
    console.log("[!!!] CRITICAL: Crypto functions found!");
    foundFunctions.crypto.forEach(function(f) {
        console.log("[!!!]   " + f.module + "::" + f.name + " at " + f.address);
    });
}

console.log("[*] Now monitor file operations during stem generation...");

// Simple file operation monitoring
var fileOps = [];

try {
    var FindFirstFileW = Module.findExportByName("kernel32.dll", "FindFirstFileW");
    if (FindFirstFileW) {
        Interceptor.attach(FindFirstFileW, {
            onEnter: function(args) {
                try {
                    var path = args[0].readUtf16String();
                    if (path.includes(".stems")) {
                        console.log("[FILE] Looking for: " + path);
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {}

console.log("[*] Ready to monitor! Start analyzing a track for stems generation...");
"""

def on_message(message, data):
    """Handle Frida messages"""
    if message['type'] == 'send':
        print(f"[Frida] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Frida ERROR] {message}")

def main():
    print("=" * 80)
    print("Simplified Frida Hook - Stems Generation Analysis")
    print("=" * 80)
    
    try:
        print("\n[*] Attaching to Engine DJ.exe...")
        session = frida.attach("Engine DJ.exe")
        print("[+] Successfully attached!")
    except frida.ProcessNotFoundError:
        print("[-] Engine DJ.exe not running!")
        print("\nStart Engine DJ Desktop first!")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    
    try:
        script = session.create_script(FRIDA_SCRIPT)
        script.on('message', on_message)
        script.load()
        print("[+] Frida script loaded!\n")
    except Exception as e:
        print(f"[-] Error loading script: {e}")
        sys.exit(1)
    
    print("=" * 80)
    print("WHAT TO DO NOW:")
    print("=" * 80)
    print("""
1. Look at the output above for:
   - [STEM] functions (stem separation)
   - [CRYPTO!!!] functions (encryption/decryption!) ← MOST IMPORTANT
   - [CODEC] functions (AAC encoding)
   
2. In Engine DJ, right-click a track and select "Analyze & Create Stems"

3. Watch this console for:
   - File operations
   - Function calls
   - Any [CRYPTO!!!] or [STEM] activity

4. If you see [CRYPTO!!!] functions, note their names and addresses

5. Take a screenshot of the output or copy the function names

6. Go back to Ghidra and search for those function names

Press Ctrl+C to stop.
""")
    print("=" * 80 + "\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()
        print("[+] Done!")

if __name__ == '__main__':
    main()
