"""
Frida script to hook Engine DJ and intercept stems decryption

Usage:
1. Install Frida: pip install frida-tools
2. Start Engine DJ Desktop
3. Run: python frida_hook_engine_dj.py
4. Play a stems file in Engine DJ
5. Check output for decrypted data or key material
"""

import frida
import sys

# Frida JavaScript to inject into Engine DJ process
FRIDA_SCRIPT = """
console.log("[*] Frida script loaded - Hooking Engine DJ");

// Hook file operations
var kernel32 = Process.getModuleByName('kernel32.dll');

// Hook CreateFileW to detect .stems file opens
var CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter: function(args) {
            var filename = args[0].readUtf16String();
            if (filename && filename.toLowerCase().includes('.stems')) {
                console.log("[+] Opening .stems file: " + filename);
                this.filename = filename;
            }
        },
        onLeave: function(retval) {
            if (this.filename) {
                console.log("[+] File handle: " + retval);
            }
        }
    });
}

// Hook ReadFile to see raw data being read
var ReadFile = Module.findExportByName('kernel32.dll', 'ReadFile');
if (ReadFile) {
    Interceptor.attach(ReadFile, {
        onEnter: function(args) {
            this.buffer = args[1];
            this.bytesToRead = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (this.bytesToRead > 0 && this.bytesToRead < 10000) {
                var data = this.buffer.readByteArray(Math.min(64, this.bytesToRead));
                console.log("[+] ReadFile: " + hexdump(data, { length: 64 }));
            }
        }
    });
}

// Search for XOR operations (x86/x64 opcodes: 0x30-0x37)
// This is speculative - hooking common crypto patterns
console.log("[*] Scanning for XOR operations in memory...");

// Hook potential AAC decoder functions
// Look for common AAC decoder library names
var possibleModules = [
    'fdkaac.dll',
    'libfdk-aac.dll', 
    'avcodec.dll',
    'libavcodec.dll',
    'MediaFoundation.dll'
];

possibleModules.forEach(function(moduleName) {
    try {
        var module = Process.getModuleByName(moduleName);
        console.log("[+] Found audio module: " + moduleName + " at " + module.base);
        
        // Hook common decoder functions
        var decoderFuncs = [
            'aacDecoder_Open',
            'aacDecoder_Fill', 
            'aacDecoder_DecodeFrame',
            'aacDecoder_ConfigRaw'
        ];
        
        decoderFuncs.forEach(function(funcName) {
            try {
                var func = Module.findExportByName(moduleName, funcName);
                if (func) {
                    console.log("[+] Hooking " + funcName + " at " + func);
                    Interceptor.attach(func, {
                        onEnter: function(args) {
                            console.log("[*] " + funcName + " called");
                            console.log("    arg0: " + args[0]);
                            console.log("    arg1: " + args[1]);
                            // Dump first argument buffer
                            try {
                                var data = args[1].readByteArray(32);
                                console.log("    Data: " + hexdump(data, { length: 32 }));
                            } catch (e) {}
                        }
                    });
                }
            } catch (e) {}
        });
        
    } catch (e) {
        // Module not loaded
    }
});

// Look for any function with 'decrypt', 'xor', 'cipher' in the name
console.log("[*] Searching for crypto-related functions...");
Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase().includes('engine')) {
        console.log("[+] Found Engine module: " + module.name + " at " + module.base);
        
        // Enumerate exports
        try {
            module.enumerateExports().forEach(function(exp) {
                var name = exp.name.toLowerCase();
                if (name.includes('decrypt') || name.includes('xor') || 
                    name.includes('cipher') || name.includes('key') ||
                    name.includes('stems') || name.includes('aac')) {
                    console.log("[!] Interesting export: " + exp.name + " at " + exp.address);
                }
            });
        } catch (e) {}
    }
});

console.log("[*] Hooks installed. Play a stems file now...");
"""


def on_message(message, data):
    """Handle messages from Frida script"""
    if message['type'] == 'send':
        print(f"[Frida] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Error] {message}")
        if 'stack' in message:
            print(f"Stack: {message['stack']}")


def main():
    print("=" * 80)
    print("Engine DJ Stems Decryption - Frida Hooking")
    print("=" * 80)
    
    # Try to attach to Engine DJ process
    try:
        print("\n[*] Looking for Engine DJ process...")
        session = frida.attach("Engine DJ.exe")
        print("[+] Attached to Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[-] Engine DJ.exe not running!")
        print("\n[!] Start Engine DJ Desktop first, then run this script again.")
        print("[!] Or use: frida -f 'C:\\Program Files\\Engine DJ\\Engine DJ.exe' -l frida_script.js")
        sys.exit(1)
    
    # Inject script
    script = session.create_script(FRIDA_SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] Script loaded! Monitoring Engine DJ...")
    print("[*] Actions to try:")
    print("    1. Play a .stems track in Engine DJ")
    print("    2. Load stems into a deck")
    print("    3. Watch console for decryption hooks")
    print("\n[*] Press Ctrl+C to stop\n")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()


if __name__ == '__main__':
    main()
