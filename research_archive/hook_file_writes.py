"""
Hook file write operations to capture what's being written to .stems files.
This will show us the encrypted data being written.
"""

import frida
import sys

SCRIPT = """
console.log("[*] Starting hooks...");

var stemsFileHandles = {};

// Track when .stems files are opened
var CreateFileWPtr = Module.getExportByName("kernel32.dll", "CreateFileW");
if (CreateFileWPtr) {
    console.log("[*] Hooking CreateFileW");

    Interceptor.attach(CreateFileWPtr, {
        onEnter: function(args) {
            var filename = args[0].readUtf16String();
            this.filename = filename;
            this.isStemsFile = filename && (filename.includes(".stems") || filename.includes("stems_temp"));
        },
        onLeave: function(retval) {
            if (this.isStemsFile && retval.toInt32() != -1) {
                stemsFileHandles[retval.toString()] = this.filename;
                console.log("[+] Opened stems file: " + this.filename);
                console.log("    Handle: " + retval);
            }
        }
    });
}

// Hook WriteFile to capture what's written to .stems files
var WriteFilePtr = Module.getExportByName("kernel32.dll", "WriteFile");
if (WriteFilePtr) {
    console.log("[*] Hooking WriteFile");

    Interceptor.attach(WriteFilePtr, {
        onEnter: function(args) {
            var hFile = args[0];
            var lpBuffer = args[1];
            var nNumberOfBytesToWrite = args[2].toInt32();
            
            var handleKey = hFile.toString();
            if (stemsFileHandles[handleKey]) {
                console.log("\\n[WriteFile to .stems]");
                console.log("  File: " + stemsFileHandles[handleKey]);
                console.log("  Writing " + nNumberOfBytesToWrite + " bytes");
                
                // Show first 128 bytes of data
                if (nNumberOfBytesToWrite > 0) {
                    var bytesToShow = Math.min(nNumberOfBytesToWrite, 128);
                    console.log("  Data (first " + bytesToShow + " bytes):");
                    console.log(hexdump(lpBuffer, {length: bytesToShow, ansi: false}));
                }
            }
        }
    });
}

// Hook fwrite as well (C runtime)
try {
    var fwritePtr = Module.getExportByName(null, "fwrite");
    if (fwritePtr) {
        console.log("[*] Hooking fwrite");
    Interceptor.attach(fwritePtr, {
        onEnter: function(args) {
            var ptr = args[0];
            var size = args[1].toInt32();
            var nmemb = args[2].toInt32();
            var totalBytes = size * nmemb;
            
            if (totalBytes > 100) { // Only show significant writes
                console.log("\\n[fwrite]");
                console.log("  Writing " + totalBytes + " bytes");
                console.log("  Data (first 64 bytes):");
                console.log(hexdump(ptr, {length: Math.min(totalBytes, 64), ansi: false}));
            }
        }
    });
    }
} catch(e) {
    console.log("[!] Could not hook fwrite: " + e);
}

// Hook malloc to see allocations
try {
    var mallocPtr = Module.getExportByName(null, "malloc");
    if (mallocPtr) {
        console.log("[*] Hooking malloc");

    var largeAllocs = 0;
    Interceptor.attach(mallocPtr, {
        onEnter: function(args) {
            var size = args[0].toInt32();
            // AAC frames are typically 1000-2000 bytes
            if (size > 500 && size < 5000) {
                this.size = size;
                this.track = true;
            }
        },
        onLeave: function(retval) {
            if (this.track) {
                largeAllocs++;
                if (largeAllocs % 50 == 0) {
                    console.log("[malloc] Allocated " + this.size + " bytes at " + retval);
                }
            }
        }
    });
    }
} catch(e) {
    console.log("[!] Could not hook malloc: " + e);
}

console.log("[*] All hooks installed. Generate stems now...");
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
    
    print("[+] Attached!")
    print("[*] Installing hooks...")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("[+] Hooks active!")
    print("[*] Generate stems now and watch for file writes...")
    print("=" * 70)
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == '__main__':
    main()
