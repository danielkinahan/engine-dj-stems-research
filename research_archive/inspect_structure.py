import frida
import sys

script_code = """
console.log("[*] Deep inspection of 0xb31196 function structure...");

var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        
        if (call_count <= 3) {
            console.log("\\n[!] Call #" + call_count);
            console.log("    RCX (likely struct): " + args[0]);
            console.log("    RDX (parameter): " + args[1]);
            console.log("    R8 (buffer): " + args[2]);
            console.log("    R9: " + args[3]);
            
            // Inspect the structure at RCX
            if (args[0] && !args[0].isNull()) {
                try {
                    var struct_ptr = args[0];
                    console.log("\\n    Structure at RCX (" + struct_ptr + "):");
                    console.log("    First 256 bytes:");
                    console.log(hexdump(struct_ptr, {length: 256, ansi: false}));
                    
                    // Try to extract potential key or frame index from structure
                    var dword1 = Memory.readU32(struct_ptr);
                    var dword2 = Memory.readU32(struct_ptr.add(4));
                    var dword3 = Memory.readU32(struct_ptr.add(8));
                    var dword4 = Memory.readU32(struct_ptr.add(12));
                    
                    console.log("\\n    As DWORDs (first 16 bytes):");
                    console.log("      [0]: " + dword1 + " (0x" + dword1.toString(16) + ")");
                    console.log("      [4]: " + dword2 + " (0x" + dword2.toString(16) + ")");
                    console.log("      [8]: " + dword3 + " (0x" + dword3.toString(16) + ")");
                    console.log("      [12]: " + dword4 + " (0x" + dword4.toString(16) + ")");
                } catch(e) {
                    console.log("    [Could not read structure]");
                }
            }
            
            // Inspect the buffer at R8
            if (args[2] && !args[2].isNull()) {
                try {
                    console.log("\\n    Buffer at R8 (first 128 bytes):");
                    console.log(hexdump(args[2], {length: 128, ansi: false}));
                } catch(e) {
                    console.log("    [Could not read buffer]");
                }
            }
            
            this.struct = args[0];
            this.buffer = args[2];
        }
    },
    onLeave: function(retval) {
        // After the function returns, check if structure was modified
        if (call_count <= 3 && this.struct && !this.struct.isNull()) {
            try {
                console.log("\\n    [After function returns]");
                console.log("    Structure at RCX (now):");
                console.log("    First 256 bytes:");
                console.log(hexdump(this.struct, {length: 256, ansi: false}));
            } catch(e) {}
        }
    }
});

console.log("[*] Waiting for calls...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

def main():
    print("[*] Attaching...")
    
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
    print("[*] Create a stem file...")
    print("[*] Press Ctrl+C to stop")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

if __name__ == '__main__':
    main()
