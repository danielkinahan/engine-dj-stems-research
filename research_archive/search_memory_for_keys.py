import frida
import sys

script_code = """
console.log("[*] Searching memory for known keys...");

// Our known Key #1
var key1_bytes = [
    0x3a, 0x81, 0xb0, 0x58, 0x70, 0x0c, 0x86, 0x0e, 
    0xd3, 0xb8, 0xef, 0xe2, 0xdf, 0xb0, 0x7b, 0x61,
    0xd0, 0xae, 0xf3, 0x9e, 0x40, 0x43, 0x63, 0x29, 
    0x08, 0x7d, 0x78, 0x09, 0x97, 0x29, 0x00, 0x5a
];

// Key #2
var key2_bytes = [
    0x5d, 0x07, 0x7a, 0xd9, 0xcd, 0x39, 0x36, 0xd0, 
    0xc9, 0x58, 0xa9, 0x05, 0x08, 0x8b, 0x39, 0xf0,
    0x44, 0xf6, 0x8b, 0x3a, 0x1b, 0xd4, 0x07, 0x95, 
    0xb3, 0xca, 0x5f, 0xf8, 0x69, 0xa0, 0xa2, 0x46
];

console.log("[*] Key 1 (first 32 bytes):");
console.log("    " + key1_bytes.map(b => b.toString(16).padStart(2, '0')).join(' '));
console.log("[*] Key 2 (first 32 bytes):");
console.log("    " + key2_bytes.map(b => b.toString(16).padStart(2, '0')).join(' '));
console.log("");

var found_count = 0;

Process.enumerateRanges('r--').forEach(function(range) {
    try {
        var data = range.file ? range.file.path : "anonymous";
        
        // Search for Key 1
        Memory.scan(range.base, range.size, 
            key1_bytes.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join(' '),
            {
                onMatch: function(address, size) {
                    console.log("[+] Found Key #1 at: " + address);
                    console.log("    Range: " + range.base + "-" + range.base.add(range.size));
                    console.log("    Protection: " + range.protection);
                    console.log("    File: " + data);
                    
                    try {
                        // Read more context around it
                        console.log("    Context (64 bytes before):");
                        console.log(hexdump(address.sub(64), {length: 64, ansi: false}));
                        console.log("    The key:");
                        console.log(hexdump(address, {length: 128, ansi: false}));
                        console.log("    Context (64 bytes after):");
                        console.log(hexdump(address.add(128), {length: 64, ansi: false}));
                    } catch(e) {}
                    
                    found_count++;
                },
                onComplete: function() {}
            }
        );
        
        // Search for Key 2
        Memory.scan(range.base, range.size,
            key2_bytes.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join(' '),
            {
                onMatch: function(address, size) {
                    console.log("[+] Found Key #2 at: " + address);
                    console.log("    Range: " + range.base + "-" + range.base.add(range.size));
                    console.log("    Protection: " + range.protection);
                    console.log("    File: " + data);
                    
                    try {
                        console.log("    The key:");
                        console.log(hexdump(address, {length: 128, ansi: false}));
                    } catch(e) {}
                    
                    found_count++;
                },
                onComplete: function() {}
            }
        );
    } catch(e) {
        // Range not readable, skip
    }
});

console.log("");
if (found_count > 0) {
    console.log("[+] Found " + found_count + " key(s) in memory!");
    console.log("[*] These keys might be stored in a key schedule or table");
} else {
    console.log("[-] Keys not found in memory");
    console.log("[*] Keys might be:");
    console.log("    1. Generated on-the-fly (not stored)");
    console.log("    2. Stored in dynamically allocated memory we missed");
    console.log("    3. Computed just before XOR operation");
}

console.log("");
console.log("[*] Now let's hook the XOR operation itself...");
console.log("[*] Looking for WriteFile more carefully...");

// Get kernel32
var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

console.log("[+] Hooking WriteFile at " + WriteFile);

var write_count = 0;
var last_data = null;

Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var hFile = args[0];
        var lpBuffer = args[1];
        var nNumberOfBytesToWrite = args[2].toInt32();
        
        // Only care about large writes (AAC data)
        if (nNumberOfBytesToWrite > 1000) {
            write_count++;
            
            if (write_count <= 3) {
                console.log("\\n[!] WriteFile #" + write_count);
                console.log("    Size: " + nNumberOfBytesToWrite);
                console.log("    Buffer address: " + lpBuffer);
                console.log("    First 64 bytes:");
                console.log(hexdump(lpBuffer, {length: 64, ansi: false}));
                
                // Save this data to compare with next write
                last_data = lpBuffer;
                this.lpBuffer = lpBuffer;
                this.size = nNumberOfBytesToWrite;
            }
        }
    },
    onLeave: function(retval) {
        // Check if we can trace back who called this
        if (write_count <= 3 && this.lpBuffer) {
            try {
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                console.log("    Call stack:");
                bt.forEach(function(addr) {
                    try {
                        var module = Process.findModuleByAddress(addr);
                        if (module) {
                            var offset = addr.sub(module.base);
                            console.log("        " + module.name + "+" + offset);
                        } else {
                            console.log("        " + addr);
                        }
                    } catch(e) {
                        console.log("        " + addr);
                    }
                });
            } catch(e) {
                console.log("    [Could not get backtrace]");
            }
        }
    }
});

console.log("[*] Memory scan and hooks active!");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] Error: {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!")
        return
    
    print("[+] Attached!")
    print("[*] Injecting script...")
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Done! Now create a stem file...")
    print("[*] Press Ctrl+C to stop")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

if __name__ == '__main__':
    main()
