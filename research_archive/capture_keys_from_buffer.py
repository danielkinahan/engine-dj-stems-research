import frida
import sys

script_code = """
console.log("[*] Capturing generated keys from buffer...");

var engine_dj = Process.getModuleByName("Engine DJ.exe");
var addr_b31196 = engine_dj.base.add(0xb31196);

var call_count = 0;
var keys_captured = [];

Interceptor.attach(addr_b31196, {
    onEnter: function(args) {
        call_count++;
        this.buffer = args[2];  // R8
        this.call_num = call_count;
    },
    onLeave: function(retval) {
        if (this.buffer && !this.buffer.isNull() && this.call_num <= 10) {
            try {
                // Read a large chunk from the buffer to find the key
                var data = Memory.readByteArray(this.buffer, 512);
                var hex_str = "";
                
                for (var i = 0; i < 512; i++) {
                    var byte = data[i] & 0xFF;
                    hex_str += byte.toString(16).padStart(2, '0');
                    if ((i + 1) % 16 === 0) hex_str += "\\n";
                }
                
                console.log("\\n[!] Frame " + this.call_num + " - Buffer at return:");
                console.log("    Address: " + this.buffer);
                console.log("    First 512 bytes (hex):");
                console.log(hex_str);
                
                // Try to find 128-byte key pattern
                // Keys should look random, so scan for likely positions
                var likely_key_start = -1;
                
                // Check common offsets
                var offsets_to_check = [0, 64, 128, 256, 320, 384];
                
                console.log("\\n    Scanning for likely 128-byte key...");
                offsets_to_check.forEach(function(offset) {
                    if (offset + 128 <= 512) {
                        var section = Memory.readByteArray(this.buffer.add(offset), 128);
                        
                        // Calculate entropy (randomness) - real keys have high entropy
                        var byte_counts = {};
                        var unique_bytes = 0;
                        for (var i = 0; i < 128; i++) {
                            var b = section[i] & 0xFF;
                            byte_counts[b] = (byte_counts[b] || 0) + 1;
                        }
                        for (var b in byte_counts) {
                            unique_bytes++;
                        }
                        
                        console.log("      Offset 0x" + offset.toString(16).padStart(3, '0') + ": " + unique_bytes + " unique bytes");
                        
                        if (unique_bytes >= 100) {
                            // Likely a key!
                            var key_hex = "";
                            for (var i = 0; i < 128; i++) {
                                key_hex += (section[i] & 0xFF).toString(16).padStart(2, '0');
                                if ((i + 1) % 16 === 0) key_hex += "\\n";
                            }
                            console.log("        [LIKELY KEY at offset 0x" + offset.toString(16) + "]");
                            console.log(key_hex);
                        }
                    }
                });
                
            } catch(e) {
                console.log("    [Error reading buffer: " + e + "]");
            }
        }
    }
});

console.log("[*] Waiting for function calls...");
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
