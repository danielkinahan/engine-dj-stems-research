import frida
import sys

script_code = """
console.log("[*] Hooking key Engine DJ functions...");

// Get the base address of Engine DJ
var engine_dj = Process.getModuleByName("Engine DJ.exe");
console.log("[+] Engine DJ base: " + engine_dj.base);

// Key functions we identified from WriteFile call stack
var addr_b2e6df = engine_dj.base.add(0xb2e6df);
var addr_b31196 = engine_dj.base.add(0xb31196);

console.log("[+] Target addresses:");
console.log("    0xb2e6df: " + addr_b2e6df);
console.log("    0xb31196: " + addr_b31196);

// Hook function at 0xb2e6df
console.log("\\n[*] Hooking 0xb2e6df...");
Interceptor.attach(addr_b2e6df, {
    onEnter: function(args) {
        console.log("\\n[!] 0xb2e6df called!");
        console.log("    RCX: " + args[0]);
        console.log("    RDX: " + args[1]);
        console.log("    R8:  " + args[2]);
        console.log("    R9:  " + args[3]);
        
        // Try to determine what these arguments are
        if (args[0] && !args[0].isNull()) {
            try {
                // Could be a buffer/structure
                var data = Memory.readByteArray(args[0], 64);
                console.log("    Memory at RCX (first 64 bytes):");
                console.log(hexdump(args[0], {length: 64, ansi: false}));
            } catch(e) {}
        }
    },
    onLeave: function(retval) {
        console.log("    Return: " + retval);
    }
});

// Hook function at 0xb31196 (likely key generation or encryption setup)
console.log("[*] Hooking 0xb31196...");
Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        console.log("\\n[!] 0xb31196 called!");
        console.log("    RCX: " + args[0]);
        console.log("    RDX: " + args[1]);
        console.log("    R8:  " + args[2]);
        console.log("    R9:  " + args[3]);
    },
    onLeave: function(retval) {
        console.log("    Return: " + retval);
    }
});

console.log("\\n[*] Hooks installed. Create a stem file now...");
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
