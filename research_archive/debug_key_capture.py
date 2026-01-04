import frida
import sys
import time

script_code = """
console.log("[*] Starting simplified key capture...");

var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;
var printed_count = 0;

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        this.buffer = args[2];
        this.rcx = args[0];
        this.rdx = args[1];
    },
    onLeave: function(retval) {
        // Only print first 10 calls
        if (printed_count < 10) {
            printed_count++;
            
            console.log("\\n========== CALL " + printed_count + " ==========");
            console.log("Total calls so far: " + call_count);
            console.log("RCX: " + this.rcx);
            console.log("RDX: " + this.rdx);
            console.log("R8 (buffer): " + this.buffer);
            console.log("Return: " + retval);
            
            // Try to dump buffer memory
            try {
                if (this.buffer && !this.buffer.isNull()) {
                    console.log("\\nBuffer contents (256 bytes):");
                    console.log(hexdump(this.buffer, {length: 256, ansi: false}));
                } else {
                    console.log("[Buffer is null]");
                }
            } catch(e) {
                console.log("[Error reading buffer: " + e.message + "]");
            }
        }
        
        // Every 500 calls, print status
        if (call_count % 500 === 0) {
            console.log("[...] " + call_count + " calls so far...");
        }
    }
});

console.log("[*] Hook installed. Waiting for calls...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
        sys.stdout.flush()

def main():
    print("[*] Attaching to Engine DJ...", flush=True)
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!", flush=True)
        return
    
    print("[+] Attached!", flush=True)
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Script loaded - Create a stem file now", flush=True)
    print("[*] Auto-exit in 120 seconds or Ctrl+C to stop", flush=True)
    
    try:
        for i in range(120):
            time.sleep(1)
            if i > 0 and i % 30 == 0:
                print(f"[...waiting {i}s...]", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted", flush=True)
    finally:
        print("[*] Detaching...", flush=True)
        session.detach()
        print("[*] Done", flush=True)

if __name__ == '__main__':
    main()
