"""
Save packet data and file writes to disk for offline analysis.
"""

import frida
import sys
import os

SCRIPT = """
console.log("[*] Saving packet and write data to files...");

var avcodec = Process.getModuleByName("avcodec-58.dll");
var avcodec_receive_packet = avcodec.getExportByName("avcodec_receive_packet");

var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

var packetCount = 0;
var largeWriteCount = 0;

// Hook packets
Interceptor.attach(avcodec_receive_packet, {
    onEnter: function(args) {
        this.pkt = args[1];
    },
    onLeave: function(retval) {
        if (retval.toInt32() == 0 && this.pkt) {
            packetCount++;
            
            var data_ptr = this.pkt.add(0x18).readPointer();
            var size = this.pkt.add(0x20).readInt();
            
            // Save first 10 packets
            if (packetCount <= 10 && size > 0 && size < 10000) {
                console.log("[Packet #" + packetCount + "] size=" + size);
                
                // Send packet data to Python (send as separate message with data)
                send({
                    type: 'packet',
                    id: packetCount,
                    size: size
                }, Memory.readByteArray(data_ptr, size));
            } else if (packetCount % 100 == 0) {
                console.log("[Packet #" + packetCount + "]");
            }
        }
    }
});

// Hook large writes (encrypted mdat)
Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var lpBuffer = args[1];
        var nNumberOfBytesToWrite = args[2].toInt32();
        
        // Capture large writes (> 100KB, likely the full mdat write)
        if (nNumberOfBytesToWrite > 100000) {
            largeWriteCount++;
            console.log("[WriteFile] Large write: " + nNumberOfBytesToWrite + " bytes");
            
            // Send to Python - first 50KB should cover first 10 frames
            var dataToSave = Math.min(nNumberOfBytesToWrite, 50000);
            send({
                type: 'write',
                id: largeWriteCount,
                totalSize: nNumberOfBytesToWrite,
                dataSaved: dataToSave
            }, Memory.readByteArray(lpBuffer, dataToSave));
        }
    }
});

console.log("[*] Hooks ready! Generate stems now...");
"""

output_dir = "frida_capture"
os.makedirs(output_dir, exist_ok=True)

def on_message(message, data):
    if message['type'] == 'send':
        payload = message.get('payload')
        
        if isinstance(payload, dict):
            msg_type = payload.get('type')
            
            if msg_type == 'packet':
                # Save packet data
                packet_id = payload['id']
                filename = os.path.join(output_dir, f"packet_{packet_id:02d}.bin")
                with open(filename, 'wb') as f:
                    f.write(data)
                print(f"[Python] Saved Packet #{packet_id} to {filename} ({len(data)} bytes)")
            
            elif msg_type == 'write':
                # Save write data
                write_id = payload['id']
                filename = os.path.join(output_dir, f"write_{write_id:02d}.bin")
                with open(filename, 'wb') as f:
                    f.write(data)
                total = payload['totalSize']
                saved = payload['dataSaved']
                print(f"[Python] Saved WriteFile #{write_id} to {filename} ({saved}/{total} bytes)")
        else:
            print(payload)
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ.exe not found.")
        return
    
    print(f"[+] Attached! Saving data to: {output_dir}/")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] Generate stems now (any track, 10+ seconds)")
    print("[*] Press Ctrl+C when done\n")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()
        print(f"\n[+] Data saved to {output_dir}/")
        print(f"[+] Run: python extract_keys_from_capture.py")

if __name__ == '__main__':
    main()
