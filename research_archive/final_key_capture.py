import frida
import sys
import time

script_code = """
var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;
var captured_keys = [];

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        this.buffer = args[2];
        this.call_num = ++call_count;
    },
    onLeave: function(retval) {
        if (this.call_num <= 5 && this.buffer && !this.buffer.isNull()) {
            try {
                var hex = "";
                for (var i = 0; i < 128; i++) {
                    var b = Memory.readU8(this.buffer.add(i));
                    hex += b.toString(16).padStart(2, '0');
                }
                send({type: "key", frame: this.call_num, hex: hex});
            } catch(e) {
                send({type: "error", frame: this.call_num, msg: e.message});
            }
        }
        
        if (this.call_num % 100 === 0) {
            send({type: "status", count: call_count});
        }
    }
});

send({type: "ready"});
"""

def on_message(message, data):
    msg = message['payload']
    if msg['type'] == 'ready':
        print("[+] Frida hook ready - CREATE STEM FILE NOW!", flush=True)
    elif msg['type'] == 'key':
        print(f"\n[!] Frame {msg['frame']} key (128 bytes):")
        print(msg['hex'], flush=True)
    elif msg['type'] == 'status':
        print(f"[...] {msg['count']} calls processed", flush=True)
    elif msg['type'] == 'error':
        print(f"[!] Error on frame {msg['frame']}: {msg['msg']}", flush=True)

try:
    print("[*] Attaching...", flush=True)
    session = frida.attach("Engine DJ.exe")
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[*] Running for 90 seconds... CREATE A STEM FILE NOW!", flush=True)
    time.sleep(90)
    
except KeyboardInterrupt:
    print("\n[*] Stopped", flush=True)
except Exception as e:
    print(f"[!] Error: {e}", flush=True)
finally:
    try:
        session.detach()
    except:
        pass
