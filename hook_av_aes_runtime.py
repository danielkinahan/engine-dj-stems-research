#!/usr/bin/env python3
"""
Frida hook to capture AES-128 key from Engine DJ.exe when it calls av_aes_crypt.

This hooks the FFmpeg av_aes_* functions that were found to be called by
function 14141d940 during stems encryption/decryption.

Usage on Windows:
  1. Install Frida: pip install frida frida-tools
  2. Save as hook_av_aes_capture.js (JavaScript version)
  3. Run: frida -n "Engine DJ.exe" -l hook_av_aes_capture.js
  4. Open a stems file in Engine DJ
  5. Check terminal for captured key
"""

FRIDA_SCRIPT = """
// Hook av_aes_init to capture AES key setup
var av_aes_init = Module.findExportByName("avutil-56.dll", "av_aes_init");
var av_aes_crypt = Module.findExportByName("avutil-56.dll", "av_aes_crypt");
var av_aes_alloc = Module.findExportByName("avutil-56.dll", "av_aes_alloc");

send("[*] Searching for FFmpeg AES functions...");
send("    av_aes_alloc: " + (av_aes_alloc ? av_aes_alloc : "NOT FOUND"));
send("    av_aes_init:  " + (av_aes_init ? av_aes_init : "NOT FOUND"));
send("    av_aes_crypt: " + (av_aes_crypt ? av_aes_crypt : "NOT FOUND"));

var keys_captured = {};
var aes_context_to_key = {};

if (av_aes_init) {
    Interceptor.attach(av_aes_init, {
        onEnter: function(args) {
            // av_aes_init(AVAES *a, const uint8_t *key, int key_bits, int decrypt)
            var a = args[0];           // AVAES* context pointer
            var key_ptr = args[1];     // uint8_t *key
            var key_bits = args[2].toInt32();
            var decrypt = args[3].toInt32();  // 0=encrypt, 1=decrypt
            
            if (key_bits === 128 && !key_ptr.isNull()) {
                try {
                    var key_bytes = Memory.readByteArray(key_ptr, 16);
                    var key_array = new Uint8Array(key_bytes);
                    var key_hex = Array.from(key_array)
                        .map(b => ('0' + b.toString(16)).slice(-2).toUpperCase())
                        .join(' ');
                    
                    // Store for reference
                    aes_context_to_key[a.toString()] = key_hex;
                    
                    send("[+] av_aes_init called with 128-bit key:");
                    send("    Context: " + a);
                    send("    Key: " + key_hex);
                    send("    Mode: " + (decrypt ? "DECRYPT (1)" : "ENCRYPT (0)"));
                    
                    keys_captured[key_hex] = true;
                } catch(e) {
                    send("[!] Error reading key: " + e);
                }
            }
        },
        onLeave: function(retval) {
            // Optional: log return
        }
    });
}

if (av_aes_crypt) {
    var call_count = 0;
    Interceptor.attach(av_aes_crypt, {
        onEnter: function(args) {
            call_count++;
            
            // av_aes_crypt(AVAES *a, uint8_t *dst, const uint8_t *src, int count, uint8_t *iv, int decrypt)
            var a = args[0];       // AVAES* context
            var dst = args[1];     // output buffer
            var src = args[2];     // input buffer
            var count = args[3].toInt32();  // number of AES blocks (count * 16)
            var iv = args[4];      // IV pointer (null if ECB)
            var decrypt = args[5].toInt32();
            
            if (call_count <= 10) {  // Log first 10 calls
                var key_info = aes_context_to_key[a.toString()] || "unknown";
                send("[*] av_aes_crypt call #" + call_count + ":");
                send("    Blocks: " + count + " (" + (count * 16) + " bytes)");
                send("    Mode: " + (decrypt ? "DECRYPT" : "ENCRYPT"));
                send("    IV: " + (iv.isNull() ? "NULL (ECB mode)" : iv));
                send("    Key: " + key_info);
                
                // Try to dump first 32 bytes of input/output
                if (src && !src.isNull() && count > 0) {
                    try {
                        var src_sample = Memory.readByteArray(src, Math.min(32, count * 16));
                        var src_hex = Array.from(new Uint8Array(src_sample))
                            .map(b => ('0' + b.toString(16)).slice(-2).toUpperCase())
                            .join(' ');
                        send("    Input[0:32]: " + src_hex.substring(0, 96));
                    } catch(e) {}
                }
            }
        }
    });
}

send("[*] Hooks installed. Open a stems file in Engine DJ...");
send("[*] Looking for av_aes function calls during decryption...");
send("");
"""

if __name__ == "__main__":
    import sys
    try:
        import frida
        
        print("[*] Frida AES Key Capture for Engine DJ.exe")
        print("=" * 70)
        
        # Get the local device
        device = frida.get_local_device()
        
        # Find Engine DJ.exe process
        process_name = "Engine DJ.exe"
        try:
            pid = device.spawn([process_name])
            print(f"[+] Spawned {process_name} with PID {pid}")
            session = device.attach(pid)
        except:
            # Try to attach to existing process
            print(f"[*] Trying to attach to running {process_name}...")
            processes = device.enumerate_processes()
            pid = None
            for p in processes:
                if process_name.lower() in p.name.lower():
                    pid = p.pid
                    print(f"[+] Found {p.name} (PID {pid})")
                    break
            
            if pid is None:
                print(f"[!] {process_name} not found. Please start it first.")
                sys.exit(1)
            
            session = device.attach(pid)
        
        # Create and load script
        script = session.create_script(FRIDA_SCRIPT)
        script.on("message", lambda message, data: print(message.get("payload", message)))
        script.load()
        
        if 'pid' in locals():
            device.resume(pid)
        
        print("\n[+] Frida hooks installed and active!")
        print("[*] Now open a .stems file in Engine DJ to trigger the hooks.")
        print("[*] Press Ctrl+C to exit.\n")
        
        import time
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            
    except ImportError:
        print("[!] Frida not installed. Install with: pip install frida frida-tools")
        print("\n[*] Or run the JavaScript version directly (on Windows):")
        print("    frida -n 'Engine DJ.exe' -l hook_av_aes_capture.js")
