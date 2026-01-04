import frida
import sys

script_code = """
console.log("[*] Hooking WriteFile for AAC data...");

var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

console.log("[+] Hooking WriteFile at " + WriteFile);

var aac_write_count = 0;
var captured_addresses = [];

Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var hFile = args[0];
        var lpBuffer = args[1];
        var nNumberOfBytesToWrite = args[2].toInt32();
        
        // Look for AAC packet-sized writes (1000-2000 bytes)
        if (nNumberOfBytesToWrite >= 1300 && nNumberOfBytesToWrite <= 2000) {
            aac_write_count++;
            
            if (aac_write_count <= 5) {
                console.log("\\n[!] AAC WriteFile #" + aac_write_count);
                console.log("    Size: " + nNumberOfBytesToWrite + " bytes");
                console.log("    Buffer: " + lpBuffer);
                console.log("    First 128 bytes (encrypted):");
                console.log(hexdump(lpBuffer, {length: 128, ansi: false}));
                
                // Capture the call stack to find encryption function
                try {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    console.log("\\n    Call stack:");
                    for (var i = 0; i < Math.min(bt.length, 10); i++) {
                        var addr = bt[i];
                        try {
                            var module = Process.findModuleByAddress(addr);
                            if (module && module.name === "Engine DJ.exe") {
                                var offset = addr.sub(module.base);
                                console.log("        [" + i + "] Engine DJ.exe+" + offset + " (" + addr + ")");
                                
                                // Save addresses for later analysis
                                if (i <= 5) {
                                    captured_addresses.push({
                                        index: i,
                                        offset: offset.toString(),
                                        address: addr.toString()
                                    });
                                }
                            } else if (module) {
                                console.log("        [" + i + "] " + module.name + "+" + addr.sub(module.base));
                            }
                        } catch(e) {}
                    }
                } catch(e) {
                    console.log("    [Could not get backtrace: " + e + "]");
                }
                
                this.lpBuffer = lpBuffer;
                this.size = nNumberOfBytesToWrite;
            }
        }
    },
    onLeave: function(retval) {
        // After first few AAC writes, try to set breakpoint on encryption function
        if (aac_write_count === 1 && captured_addresses.length > 0) {
            console.log("\\n[*] Identified potential encryption functions:");
            captured_addresses.forEach(function(item) {
                console.log("    [" + item.index + "] Engine DJ.exe+" + item.offset);
            });
        }
    }
});

console.log("[*] Waiting for AAC data writes...");
console.log("[*] Create a stem file now...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!")
        return
    
    print("[+] Attached!")
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Script loaded!")
    print("[*] Now create a stem file...")
    print("[*] Press Ctrl+C to stop")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

if __name__ == '__main__':
    main()
