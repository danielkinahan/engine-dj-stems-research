import frida
import sys
import time

script_code = """
console.log("[*] Hooking Windows CNG (bcryptPrimitives.dll)...");

// Hook bcryptPrimitives.dll - the actual crypto implementation
var bcryptPrimitives = Process.getModuleByName("bcryptPrimitives.dll");
console.log("[+] Found bcryptPrimitives.dll at " + bcryptPrimitives.base);

// Hook random number generation
try {
    var ProcessPrng = bcryptPrimitives.getExportByName("ProcessPrng");
    if (ProcessPrng) {
        console.log("[+] Hooking ProcessPrng (RNG function)");
        
        Interceptor.attach(ProcessPrng, {
            onEnter: function(args) {
                console.log("\\n[!] ProcessPrng called!");
                console.log("    Buffer: " + args[0]);
                console.log("    Size: " + args[1]);
                this.buffer = args[0];
                this.size = args[1].toInt32();
            },
            onLeave: function(retval) {
                if (this.buffer && this.size > 0 && this.size <= 256) {
                    try {
                        console.log("    Generated random bytes (" + this.size + " bytes):");
                        console.log(hexdump(this.buffer, {length: this.size, ansi: false}));
                    } catch(e) {}
                }
                console.log("    Return: " + retval);
            }
        });
    }
} catch(e) {
    console.log("[-] ProcessPrng not found: " + e);
}

// Also hook bcrypt.dll functions
var bcrypt = Process.getModuleByName("bcrypt.dll");
console.log("[+] Found bcrypt.dll at " + bcrypt.base);

// BCryptGenRandom - generates random numbers
try {
    var BCryptGenRandom = bcrypt.getExportByName("BCryptGenRandom");
    if (BCryptGenRandom) {
        console.log("[+] Hooking BCryptGenRandom");
        
        Interceptor.attach(BCryptGenRandom, {
            onEnter: function(args) {
                console.log("\\n[!] BCryptGenRandom called!");
                console.log("    hAlgorithm: " + args[0]);
                console.log("    pbBuffer: " + args[1]);
                console.log("    cbBuffer: " + args[2]);
                console.log("    dwFlags: " + args[3]);
                this.buffer = args[1];
                this.size = args[2].toInt32();
            },
            onLeave: function(retval) {
                console.log("    Return: " + retval);
                if (this.buffer && this.size > 0 && this.size <= 256) {
                    try {
                        console.log("    Generated random bytes (" + this.size + " bytes):");
                        console.log(hexdump(this.buffer, {length: this.size, ansi: false}));
                    } catch(e) {}
                }
            }
        });
    }
} catch(e) {
    console.log("[-] BCryptGenRandom not found: " + e);
}

// BCryptDeriveKey - key derivation
try {
    var BCryptDeriveKey = bcrypt.getExportByName("BCryptDeriveKey");
    if (BCryptDeriveKey) {
        console.log("[+] Hooking BCryptDeriveKey");
        
        Interceptor.attach(BCryptDeriveKey, {
            onEnter: function(args) {
                console.log("\\n[!] BCryptDeriveKey called!");
                console.log("    hSharedSecret: " + args[0]);
                console.log("    pwszKDF: " + args[1]);
                // Try to read KDF name
                try {
                    if (!args[1].isNull()) {
                        var kdf_name = args[1].readUtf16String();
                        console.log("    KDF name: " + kdf_name);
                    }
                } catch(e) {}
                console.log("    pParameterList: " + args[2]);
                console.log("    pbDerivedKey: " + args[3]);
                console.log("    cbDerivedKey: " + args[4]);
                this.out_buffer = args[3];
                this.out_size = args[4].toInt32();
            },
            onLeave: function(retval) {
                console.log("    Return: " + retval);
                if (this.out_buffer && this.out_size > 0 && this.out_size <= 256) {
                    try {
                        console.log("    Derived key (" + this.out_size + " bytes):");
                        console.log(hexdump(this.out_buffer, {length: this.out_size, ansi: false}));
                    } catch(e) {}
                }
            }
        });
    }
} catch(e) {
    console.log("[-] BCryptDeriveKey not found: " + e);
}

// BCryptHash - hash function
try {
    var BCryptHash = bcrypt.getExportByName("BCryptHash");
    if (BCryptHash) {
        console.log("[+] Hooking BCryptHash");
        
        Interceptor.attach(BCryptHash, {
            onEnter: function(args) {
                console.log("\\n[!] BCryptHash called!");
                console.log("    hAlgorithm: " + args[0]);
                console.log("    pbSecret: " + args[1]);
                console.log("    cbSecret: " + args[2]);
                console.log("    pbInput: " + args[3]);
                console.log("    cbInput: " + args[4]);
                
                var input_size = args[4].toInt32();
                if (args[3] && !args[3].isNull() && input_size > 0 && input_size <= 64) {
                    try {
                        console.log("    Input data:");
                        console.log(hexdump(args[3], {length: input_size, ansi: false}));
                    } catch(e) {}
                }
                
                this.out_buffer = args[5];
                this.out_size = args[6].toInt32();
            },
            onLeave: function(retval) {
                console.log("    Return: " + retval);
                if (this.out_buffer && this.out_size > 0 && this.out_size <= 256) {
                    try {
                        console.log("    Hash output (" + this.out_size + " bytes):");
                        console.log(hexdump(this.out_buffer, {length: this.out_size, ansi: false}));
                    } catch(e) {}
                }
            }
        });
    }
} catch(e) {
    console.log("[-] BCryptHash not found: " + e);
}

console.log("[*] Windows CNG hooks installed. Waiting for crypto operations...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!")
        return
    
    print("[+] Attached!")
    print("[*] Injecting script...")
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    
    print("[+] Script loaded!")
    print("[*] Now create a stem file in Engine DJ...")
    print("[*] Press Ctrl+C to stop")
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        session.detach()

if __name__ == '__main__':
    main()
