import frida
import sys
import time
import threading

script_code = """
console.log("[*] Hook installed - waiting for calls...");

var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        console.log("[CALL " + call_count + "] Function 0xb31196 called");
        this.buffer = args[2];
    },
    onLeave: function(retval) {
        if (this.buffer && !this.buffer.isNull()) {
            try {
                // Read 512 bytes and print as hex
                var data = Memory.readByteArray(this.buffer, 512);
                var hex = "";
                for (var i = 0; i < Math.min(512, data.length); i++) {
                    var b = data[i];
                    if (b < 16) hex += "0";
                    hex += b.toString(16);
                }
                
                console.log("[KEY_DATA_" + call_count + "]");
                // Print in chunks so it's readable
                for (var i = 0; i < hex.length; i += 64) {
                    console.log(hex.substring(i, i + 64));
                }
                console.log("[END_KEY_" + call_count + "]");
                
            } catch(e) {
                console.log("[ERROR] " + e);
            }
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        output = message['payload']
        print(output)
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
    print("[*] Will auto-exit in 60 seconds or when you press Ctrl+C", flush=True)
    
    try:
        # Wait 60 seconds or until interrupted
        for i in range(60):
            time.sleep(1)
            if i % 10 == 0 and i > 0:
                print(f"[...] Still waiting ({i}s elapsed)...", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user", flush=True)
    finally:
        print("[*] Detaching...", flush=True)
        session.detach()
        print("[*] Done", flush=True)

if __name__ == '__main__':
    main()
