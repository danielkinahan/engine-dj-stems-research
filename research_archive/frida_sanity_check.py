"""
Minimal Frida sanity check - just hook basic Windows functions.
"""

import frida
import sys
import time

SCRIPT = """
console.log("[*] Frida script loaded successfully!");
console.log("[*] Frida version: " + Frida.version);

// First, just enumerate modules
console.log("\\n[*] Enumerating loaded modules...");
var moduleCount = 0;
var foundModules = [];

Process.enumerateModules().forEach(function(module) {
    moduleCount++;
    var nameLower = module.name.toLowerCase();
    if (nameLower.includes("avcodec") || 
        nameLower.includes("bcrypt") ||
        nameLower.includes("kernel32") ||
        nameLower.includes("engine")) {
        foundModules.push(module.name + " at " + module.base);
    }
});

console.log("[*] Total modules loaded: " + moduleCount);
console.log("\\n[*] Interesting modules:");
foundModules.forEach(function(m) {
    console.log("  - " + m);
});

// Try to find an export using the proper API
console.log("\\n[*] Testing export resolution...");
try {
    var kernel32 = Process.getModuleByName("kernel32.dll");
    console.log("[+] Found kernel32.dll at " + kernel32.base);
    
    // Try to get an export
    var getTickCountAddr = kernel32.getExportByName("GetTickCount");
    console.log("[+] GetTickCount at " + getTickCountAddr);
    
    // Try to hook it
    Interceptor.attach(getTickCountAddr, {
        onEnter: function(args) {
            console.log("[*] GetTickCount called!");
        }
    });
    console.log("[+] Successfully hooked GetTickCount!");
    
} catch(e) {
    console.log("[!] Error: " + e.message);
}

console.log("\\n[*] Script initialized successfully!");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ.exe not found. Please start Engine DJ first.")
        return
    except Exception as e:
        print(f"[!] Error attaching: {e}")
        return
    
    print("[+] Attached to Engine DJ!")
    print("[*] Loading Frida script...\n")
    
    try:
        script = session.create_script(SCRIPT)
        script.on('message', on_message)
        script.load()
    except Exception as e:
        print(f"[!] Error loading script: {e}")
        return
    
    print("\n[+] Script loaded!")
    print("[*] You should see GetTickCount calls above.")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == '__main__':
    main()
