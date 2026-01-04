import frida
import sys

script_code = """
console.log("[*] Analyzing all WriteFile calls...");

var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

console.log("[+] Hooking WriteFile at " + WriteFile);

var write_count = 0;
var size_buckets = {};

Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var hFile = args[0];
        var lpBuffer = args[1];
        var nNumberOfBytesToWrite = args[2].toInt32();
        
        // Bucket sizes
        var bucket;
        if (nNumberOfBytesToWrite < 100) bucket = "<100";
        else if (nNumberOfBytesToWrite < 1000) bucket = "100-1K";
        else if (nNumberOfBytesToWrite < 10000) bucket = "1K-10K";
        else if (nNumberOfBytesToWrite < 100000) bucket = "10K-100K";
        else bucket = ">100K";
        
        size_buckets[bucket] = (size_buckets[bucket] || 0) + 1;
        
        write_count++;
        
        // Show every write
        if (write_count <= 30) {
            console.log("[" + write_count + "] WriteFile: " + nNumberOfBytesToWrite + " bytes (bucket: " + bucket + ")");
            
            // Only show content for interesting sizes
            if (nNumberOfBytesToWrite >= 800 && nNumberOfBytesToWrite <= 3000) {
                console.log("      First 64 bytes:");
                console.log(hexdump(lpBuffer, {length: 64, ansi: false}));
                
                // Get call stack for AAC-sized writes
                try {
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    console.log("      Top of stack:");
                    for (var i = 0; i < Math.min(3, bt.length); i++) {
                        var addr = bt[i];
                        var module = Process.findModuleByAddress(addr);
                        if (module && module.name === "Engine DJ.exe") {
                            var offset = addr.sub(module.base);
                            console.log("        Engine DJ.exe+" + offset);
                        }
                    }
                } catch(e) {}
            }
        }
        
        if (write_count === 50) {
            console.log("\\n[*] Summary of first 50 WriteFile calls:");
            console.log("Size bucket distribution:");
            for (var bucket in size_buckets) {
                console.log("  " + bucket + ": " + size_buckets[bucket] + " calls");
            }
        }
    }
});

console.log("[*] Waiting for WriteFile calls...");
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
