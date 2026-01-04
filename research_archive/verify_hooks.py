import frida
import sys
import time

script_code = """
var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;
var last_report = 0;

console.log("[*] Hook at " + addr_b31196 + " ready");

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        
        // Print every call for first 50, then every 100th
        if (call_count <= 50 || call_count % 100 === 0) {
            console.log("[CALL " + call_count + "] RCX=" + args[0] + " RDX=" + args[1] + " R8=" + args[2]);
        }
    }
});

// Also try to hook WriteFile to see if it's called
var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

var write_count = 0;
Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var size = args[2].toInt32();
        if (size > 500 && size < 3000) {
            write_count++;
            console.log("[WRITEFILE " + write_count + "] Size=" + size);
        }
    }
});

console.log("[*] All hooks installed");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'], flush=True)

try:
    print("[*] Attaching to Engine DJ.exe...", flush=True)
    session = frida.attach("Engine DJ.exe")
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Hooks loaded! Now create a stem file...", flush=True)
    print("[*] Watch for [CALL xxx] and [WRITEFILE xxx] messages", flush=True)
    print("[*] Press Ctrl+C to stop\n", flush=True)
    
    while True:
        time.sleep(1)
        
except KeyboardInterrupt:
    print("\n[*] Stopping...", flush=True)
    try:
        session.detach()
    except:
        pass
    print("[*] Done", flush=True)
except Exception as e:
    print(f"[!] Error: {e}", flush=True)
