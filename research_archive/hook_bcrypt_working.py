"""
Hook BCrypt and FFmpeg functions to capture stems encryption.
"""

import frida
import sys

SCRIPT = """
console.log("[*] Loading BCrypt/FFmpeg hooks...");

// Get bcrypt.dll module
var bcrypt = Process.getModuleByName("bcrypt.dll");
console.log("[+] Found bcrypt.dll at " + bcrypt.base);

// Get avcodec-58.dll module
var avcodec = Process.getModuleByName("avcodec-58.dll");
console.log("[+] Found avcodec-58.dll at " + avcodec.base);

// Hook BCryptGenRandom
try {
    var BCryptGenRandom = bcrypt.getExportByName("BCryptGenRandom");
    console.log("[+] Found BCryptGenRandom at " + BCryptGenRandom);
    
    Interceptor.attach(BCryptGenRandom, {
        onEnter: function(args) {
            var cbBuffer = args[2].toInt32();
            console.log("\\n[BCryptGenRandom] Generating " + cbBuffer + " random bytes");
            this.pbBuffer = args[1];
            this.cbBuffer = cbBuffer;
        },
        onLeave: function(retval) {
            if (this.cbBuffer > 0 && this.cbBuffer < 256) {
                console.log("  Random data: " + hexdump(this.pbBuffer, {length: this.cbBuffer, ansi: false}));
            }
        }
    });
    console.log("[+] Hooked BCryptGenRandom");
} catch(e) {
    console.log("[!] Could not hook BCryptGenRandom: " + e.message);
}

// Hook BCryptDeriveKeyPBKDF2
try {
    var BCryptDeriveKeyPBKDF2 = bcrypt.getExportByName("BCryptDeriveKeyPBKDF2");
    console.log("[+] Found BCryptDeriveKeyPBKDF2 at " + BCryptDeriveKeyPBKDF2);
    
    Interceptor.attach(BCryptDeriveKeyPBKDF2, {
        onEnter: function(args) {
            var cbPassword = args[2].toInt32();
            var cbSalt = args[4].toInt32();
            var cIterations = args[5].toInt32();
            var cbDerivedKey = args[7].toInt32();
            
            console.log("\\n[!!! BCryptDeriveKeyPBKDF2 - KEY DERIVATION !!!]");
            console.log("  Password length: " + cbPassword + " bytes");
            console.log("  Salt length: " + cbSalt + " bytes");
            console.log("  Iterations: " + cIterations);
            console.log("  Derived key length: " + cbDerivedKey + " bytes");
            
            if (cbPassword > 0 && cbPassword < 256) {
                console.log("  Password/seed:");
                console.log(hexdump(args[1], {length: cbPassword, ansi: false}));
            }
            if (cbSalt > 0 && cbSalt < 256) {
                console.log("  Salt:");
                console.log(hexdump(args[3], {length: cbSalt, ansi: false}));
            }
            
            this.pbDerivedKey = args[6];
            this.cbDerivedKey = cbDerivedKey;
        },
        onLeave: function(retval) {
            if (retval.toInt32() == 0 && this.cbDerivedKey > 0 && this.cbDerivedKey < 256) {
                console.log("  Derived key:");
                console.log(hexdump(this.pbDerivedKey, {length: this.cbDerivedKey, ansi: false}));
            }
            console.log("  Return: 0x" + retval.toString(16));
        }
    });
    console.log("[+] Hooked BCryptDeriveKeyPBKDF2");
} catch(e) {
    console.log("[!] Could not hook BCryptDeriveKeyPBKDF2: " + e.message);
}

// Hook BCryptEncrypt
try {
    var BCryptEncrypt = bcrypt.getExportByName("BCryptEncrypt");
    console.log("[+] Found BCryptEncrypt at " + BCryptEncrypt);
    
    Interceptor.attach(BCryptEncrypt, {
        onEnter: function(args) {
            var cbInput = args[2].toInt32();
            console.log("\\n[BCryptEncrypt] Encrypting " + cbInput + " bytes");
            if (cbInput > 0 && cbInput < 128) {
                console.log("  Input:");
                console.log(hexdump(args[1], {length: cbInput, ansi: false}));
            }
            this.pbOutput = args[6];
            this.cbOutput = args[7].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() == 0 && this.cbOutput > 0 && this.cbOutput < 128) {
                console.log("  Encrypted output:");
                console.log(hexdump(this.pbOutput, {length: this.cbOutput, ansi: false}));
            }
        }
    });
    console.log("[+] Hooked BCryptEncrypt");
} catch(e) {
    console.log("[!] Could not hook BCryptEncrypt: " + e.message);
}

// Hook avcodec_receive_packet (gets encoded AAC frames)
try {
    var avcodec_receive_packet = avcodec.getExportByName("avcodec_receive_packet");
    console.log("[+] Found avcodec_receive_packet at " + avcodec_receive_packet);
    
    Interceptor.attach(avcodec_receive_packet, {
        onLeave: function(retval) {
            if (retval.toInt32() == 0) {
                console.log("\\n[avcodec_receive_packet] Got encoded packet");
            }
        }
    });
    console.log("[+] Hooked avcodec_receive_packet");
} catch(e) {
    console.log("[!] Could not hook avcodec_receive_packet: " + e.message);
}

console.log("\\n[*] All hooks installed!");
console.log("[*] Generate stems now and watch for BCrypt calls...");
console.log("=" + "=".repeat(69));
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ.exe not found. Please start Engine DJ first.")
        return
    
    print("[+] Attached!")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] Ready! Now generate stems in Engine DJ.")
    print("[*] Right-click a track → Create Stems")
    print("[*] Watch for BCrypt output below...\n")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == '__main__':
    main()
