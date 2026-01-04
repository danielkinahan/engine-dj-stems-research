"""
Frida script to hook BCrypt functions and capture stems encryption parameters.
Run this while generating stems to see the actual key derivation in action.
"""

import frida
import sys
import time

SCRIPT = """
// Hook BCryptGenRandom to see when random data is generated
var BCryptGenRandom = Module.findExportByName("bcrypt.dll", "BCryptGenRandom");
if (BCryptGenRandom) {
    Interceptor.attach(BCryptGenRandom, {
        onEnter: function(args) {
            var hAlgorithm = args[0];
            var pbBuffer = args[1];
            var cbBuffer = args[2].toInt32();
            var dwFlags = args[3].toInt32();
            
            console.log("\\n[BCryptGenRandom]");
            console.log("  Buffer size: " + cbBuffer + " bytes");
            console.log("  Flags: 0x" + dwFlags.toString(16));
        },
        onLeave: function(retval) {
            console.log("  Return: 0x" + retval.toString(16));
        }
    });
}

// Hook BCryptDeriveKeyPBKDF2 - THIS IS THE KEY DERIVATION!
var BCryptDeriveKeyPBKDF2 = Module.findExportByName("bcrypt.dll", "BCryptDeriveKeyPBKDF2");
if (BCryptDeriveKeyPBKDF2) {
    Interceptor.attach(BCryptDeriveKeyPBKDF2, {
        onEnter: function(args) {
            var hPrf = args[0];
            var pbPassword = args[1];
            var cbPassword = args[2].toInt32();
            var pbSalt = args[3];
            var cbSalt = args[4].toInt32();
            var cIterations = args[5];
            var pbDerivedKey = args[6];
            var cbDerivedKey = args[7].toInt32();
            
            console.log("\\n[!!! BCryptDeriveKeyPBKDF2 - KEY DERIVATION !!!]");
            console.log("  Password/Seed length: " + cbPassword + " bytes");
            if (cbPassword > 0 && cbPassword < 1000) {
                console.log("  Password hex: " + hexdump(pbPassword, {length: cbPassword, ansi: false}));
            }
            console.log("  Salt length: " + cbSalt + " bytes");
            if (cbSalt > 0 && cbSalt < 1000) {
                console.log("  Salt hex: " + hexdump(pbSalt, {length: cbSalt, ansi: false}));
            }
            console.log("  Iterations: " + cIterations);
            console.log("  Derived key length: " + cbDerivedKey + " bytes");
            
            // Store derived key buffer pointer to read in onLeave
            this.pbDerivedKey = pbDerivedKey;
            this.cbDerivedKey = cbDerivedKey;
        },
        onLeave: function(retval) {
            console.log("  Return: 0x" + retval.toString(16));
            if (retval.toInt32() == 0 && this.cbDerivedKey < 1000) {
                console.log("  Derived key: " + hexdump(this.pbDerivedKey, {length: this.cbDerivedKey, ansi: false}));
            }
        }
    });
} else {
    console.log("[WARNING] BCryptDeriveKeyPBKDF2 not found - may not be used");
}

// Hook BCryptEncrypt - THIS IS WHERE ENCRYPTION HAPPENS
var BCryptEncrypt = Module.findExportByName("bcrypt.dll", "BCryptEncrypt");
if (BCryptEncrypt) {
    Interceptor.attach(BCryptEncrypt, {
        onEnter: function(args) {
            var hKey = args[0];
            var pbInput = args[1];
            var cbInput = args[2].toInt32();
            var pPaddingInfo = args[3];
            var pbIV = args[4];
            var cbIV = args[5].toInt32();
            var pbOutput = args[6];
            var cbOutput = args[7].toInt32();
            
            console.log("\\n[BCryptEncrypt]");
            console.log("  Input length: " + cbInput + " bytes");
            if (cbInput > 0 && cbInput < 200) {
                console.log("  Input (first bytes): " + hexdump(pbInput, {length: Math.min(cbInput, 64), ansi: false}));
            }
            console.log("  Output buffer size: " + cbOutput + " bytes");
            if (pbIV && cbIV > 0) {
                console.log("  IV length: " + cbIV + " bytes");
                console.log("  IV: " + hexdump(pbIV, {length: cbIV, ansi: false}));
            }
            
            this.pbOutput = pbOutput;
            this.cbOutput = cbOutput;
        },
        onLeave: function(retval) {
            if (retval.toInt32() == 0 && this.pbOutput && this.cbOutput > 0 && this.cbOutput < 200) {
                console.log("  Encrypted output: " + hexdump(this.pbOutput, {length: Math.min(this.cbOutput, 64), ansi: false}));
            }
        }
    });
} else {
    console.log("[WARNING] BCryptEncrypt not found - may not be used");
}

// Hook BCryptHashData - for hash-based key derivation
var BCryptHashData = Module.findExportByName("bcrypt.dll", "BCryptHashData");
if (BCryptHashData) {
    Interceptor.attach(BCryptHashData, {
        onEnter: function(args) {
            var hHash = args[0];
            var pbInput = args[1];
            var cbInput = args[2].toInt32();
            
            console.log("\\n[BCryptHashData]");
            console.log("  Input length: " + cbInput + " bytes");
            if (cbInput > 0 && cbInput < 200) {
                console.log("  Data: " + hexdump(pbInput, {length: Math.min(cbInput, 64), ansi: false}));
            }
        }
    });
}

console.log("[*] Hooks installed. Generate stems now...");
console.log("[*] Watching for BCrypt encryption calls...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("[*] Looking for Engine DJ process...")
    
    try:
        # Try to attach to running Engine DJ
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ.exe not found. Please start Engine DJ Desktop first.")
        return
    
    print("[+] Attached to Engine DJ")
    print("[*] Installing BCrypt hooks...")
    
    script = session.create_script(SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print("[+] Hooks active!")
    print("[*] Now generate stems in Engine DJ (right-click track → Create Stems)")
    print("[*] Watch for BCrypt calls below...")
    print("=" * 70)
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()

if __name__ == '__main__':
    main()
