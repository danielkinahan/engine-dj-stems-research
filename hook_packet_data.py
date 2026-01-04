"""
Capture encoded AAC packets and look for encryption/XOR operations.
"""

import frida
import sys

SCRIPT = """
console.log("[*] Hooking FFmpeg packet handling...");

var avcodec = Process.getModuleByName("avcodec-58.dll");
var avcodec_receive_packet = avcodec.getExportByName("avcodec_receive_packet");

var packetCount = 0;

Interceptor.attach(avcodec_receive_packet, {
    onEnter: function(args) {
        this.pkt = args[1];  // AVPacket* pointer
    },
    onLeave: function(retval) {
        if (retval.toInt32() == 0 && this.pkt) {
            packetCount++;
            
            // AVPacket structure (simplified):
            // offset 0x00: AVBufferRef* buf
            // offset 0x08: int64_t pts
            // offset 0x10: int64_t dts
            // offset 0x18: uint8_t* data
            // offset 0x20: int size
            
            var data_ptr = this.pkt.add(0x18).readPointer();
            var size = this.pkt.add(0x20).readInt();
            
            // Show first 25000 frames in detail (capture all keys)
            if (packetCount <= 25000) {
                console.log("\\n[Packet #" + packetCount + "] (UNENCRYPTED FROM FFMPEG)");
                console.log("  Size: " + size + " bytes");
                console.log("  Data pointer: " + data_ptr);
                
                if (size > 0 && size < 10000) {
                    console.log("  First 128 bytes:");
                    console.log(hexdump(data_ptr, {length: Math.min(size, 128), ansi: false}));
                    
                    // Store the original data to compare later
                    var original = Memory.readByteArray(data_ptr, Math.min(size, 64));
                    
                    // Set a breakpoint AFTER this call to see if data changes
                    // Save data for comparison
                    send({
                        type: 'packet',
                        id: packetCount,
                        size: size,
                        data: Array.from(new Uint8Array(original))
                    });
                }
            } else if (packetCount % 100 == 0) {
                console.log("[Packet #" + packetCount + "] size=" + size);
            }
        }
    }
});

// Hook memcpy to see if packet data is copied/modified
var msvcrt = null;
try {
    // Try to find msvcrt
    Process.enumerateModules().forEach(function(m) {
        if (m.name.toLowerCase().includes("msvcr") || m.name.toLowerCase().includes("vcruntime")) {
            msvcrt = m;
        }
    });
    
    if (msvcrt) {
        console.log("[+] Found " + msvcrt.name);
        var memcpy = msvcrt.getExportByName("memcpy");
        
        Interceptor.attach(memcpy, {
            onEnter: function(args) {
                var size = args[2].toInt32();
                // Look for copies of AAC frame sizes (typically 1000-8000 bytes)
                if (size > 500 && size < 10000) {
                    this.dest = args[0];
                    this.src = args[1];
                    this.size = size;
                    this.track = true;
                }
            },
            onLeave: function(retval) {
                if (this.track) {
                    // Check if data was modified during copy (would indicate inline XOR)
                    // This would be very slow, so just log large copies
                    console.log("[memcpy] " + this.size + " bytes from " + this.src + " to " + this.dest);
                }
            }
        });
        console.log("[+] Hooked memcpy");
    }
} catch(e) {
    console.log("[!] Could not hook memcpy: " + e.message);
}

// Try to find file write operations
var kernel32 = Process.getModuleByName("kernel32.dll");
var WriteFile = kernel32.getExportByName("WriteFile");

var stemsFileHandle = null;

var writeCount = 0;
Interceptor.attach(WriteFile, {
    onEnter: function(args) {
        var hFile = args[0];
        var lpBuffer = args[1];
        var nNumberOfBytesToWrite = args[2].toInt32();
        
        writeCount++;
        
        // Show ALL writes during generation
        if (nNumberOfBytesToWrite > 100) {
            console.log("\\n[WriteFile #" + writeCount + "] Writing " + nNumberOfBytesToWrite + " bytes");
            
            // Show first bytes
            var showBytes = Math.min(nNumberOfBytesToWrite, 128);
            console.log("  Data:");
            console.log(hexdump(lpBuffer, {length: showBytes, ansi: false}));
            
            // Check if this looks like ADTS (AAC frame)
            var firstByte = lpBuffer.readU8();
            var secondByte = lpBuffer.add(1).readU8();
            
            if (firstByte == 0xFF && (secondByte & 0xF0) == 0xF0) {
                console.log("  *** LOOKS LIKE ADTS SYNC WORD (AAC FRAME) ***");
            }
        }
    }
});
console.log("[+] Hooked WriteFile");

console.log("\\n[*] Hooks ready! Generate stems now...");
console.log("[*] We'll compare FFmpeg output vs file writes to see encryption");
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message.get('payload')
        if isinstance(payload, dict) and payload.get('type') == 'packet':
            packet_id = payload['id']
            packet_data = payload['data']
            print(f"\n[Python] Saved packet #{packet_id} data ({len(packet_data)} bytes)")
            # We could compare this with WriteFile data later
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
    
    print("[+] Attached!")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] Generate stems now!")
    print("[*] Watch for packet data (unencrypted) vs file writes (encrypted)")
    print("=" * 70)
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == '__main__':
    main()
