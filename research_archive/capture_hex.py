"""
Print packet hex data directly (no binary transfer).
"""

import frida
import sys

output_file = None

SCRIPT = """
console.log("[*] Capturing packet hex data...");

var avcodec = Process.getModuleByName("avcodec-58.dll");
var avcodec_receive_packet = avcodec.getExportByName("avcodec_receive_packet");

var packetCount = 0;
var savedPackets = 0;

Interceptor.attach(avcodec_receive_packet, {
    onEnter: function(args) {
        this.pkt = args[1];
    },
    onLeave: function(retval) {
        if (retval.toInt32() == 0 && this.pkt && savedPackets < 10) {
            packetCount++;
            
            var data_ptr = this.pkt.add(0x18).readPointer();
            var size = this.pkt.add(0x20).readInt();
            
            if (size > 0 && size < 10000) {
                savedPackets++;
                console.log("\\n=== PACKET " + savedPackets + " ===");
                console.log("SIZE: " + size);
                console.log("HEX:");
                console.log(hexdump(data_ptr, {length: Math.min(size, 2000), ansi: false}));
            }
        } else if (packetCount % 100 == 0) {
            console.log("[Packet #" + packetCount + "]");
        }
    }
});

console.log("[*] Hook ready! Generate stems...");
"""

def on_message(msg, data):
    global output_file
    if msg['type'] == 'send':
        output = str(msg.get('payload', ''))
        print(output)  # Print to console
        if output_file:
            output_file.write(output + '\n')
            output_file.flush()
    else:
        error = f"[ERROR] {msg.get('stack', msg)}"
        print(error)
        if output_file:
            output_file.write(error + '\n')
            output_file.flush()

def main():
    global output_file
    
    filename = "packets_hex.txt"
    output_file = open(filename, 'w', encoding='utf-8', buffering=1)  # Line buffering
    
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ.exe not found.")
        output_file.close()
        return
    
    print("[+] Attached!")
    print(f"[*] Writing output to: {filename}")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] Generate stems now!")
    print("[*] Will capture first 10 packets")
    print("[*] Press Ctrl+C when done\n")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print(f"\n[*] Done! Output saved to: {filename}")
        session.detach()
    finally:
        output_file.close()

if __name__ == '__main__':
    main()
