import frida
import sys
import time

script_code = """
var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;
var captured = [];

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        this.buffer = args[2];  // R8
        this.call_num = call_count;
    },
    onLeave: function(retval) {
        // Capture first 5 calls, buffer after function returns
        if (this.call_num >= 2600 && this.call_num <= 2605 && this.buffer && !this.buffer.isNull()) {
            try {
                // Read 256 bytes from R8 buffer
                var hex = "";
                for (var i = 0; i < 256; i++) {
                    var b = Memory.readU8(this.buffer.add(i));
                    hex += b.toString(16).padStart(2, '0');
                }
                send({type: "buffer", frame: this.call_num, hex: hex});
            } catch(e) {
                send({type: "error", frame: this.call_num, msg: String(e)});
            }
        }
    }
});

send({type: "ready"});
"""

def on_message(message, data):
    msg = message['payload']
    if msg['type'] == 'ready':
        print("[+] Ready - hook active", flush=True)
    elif msg['type'] == 'buffer':
        print(f"\n[FRAME {msg['frame']}] First 256 bytes of R8 buffer:")
        hex_str = msg['hex']
        for i in range(0, len(hex_str), 64):
            print(hex_str[i:i+64], flush=True)
    elif msg['type'] == 'error':
        print(f"[!] Error on frame {msg['frame']}: {msg['msg']}", flush=True)

try:
    print("[*] Attaching to Engine DJ.exe...", flush=True)
    session = frida.attach("Engine DJ.exe")
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Hook loaded - CREATE STEM FILE NOW!", flush=True)
    print("[*] Waiting 120 seconds (or Ctrl+C to exit)...\n", flush=True)
    
    for i in range(120):
        time.sleep(1)
        
except KeyboardInterrupt:
    print("\n[*] Stopped", flush=True)
except Exception as e:
    print(f"[!] Error: {e}", flush=True)
finally:
    try:
        session.detach()
    except:
        pass
