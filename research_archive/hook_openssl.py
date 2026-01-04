import frida
import sys
import time

# The script to inject
script_code = """
console.log("[*] Starting OpenSSL hook...");

// Find libcrypto module
var libcrypto = null;
Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase().includes('libcrypto')) {
        libcrypto = module;
        console.log("[+] Found libcrypto: " + module.name + " at " + module.base);
    }
});

if (!libcrypto) {
    console.log("[-] libcrypto not found");
} else {
    // Common OpenSSL key derivation and encryption functions
    var functions_to_hook = [
        'EVP_EncryptInit_ex',
        'EVP_EncryptUpdate',
        'EVP_EncryptFinal_ex',
        'EVP_DecryptInit_ex',
        'EVP_DecryptUpdate',
        'EVP_DecryptFinal_ex',
        'EVP_CipherInit_ex',
        'EVP_CipherUpdate',
        'EVP_CipherFinal_ex',
        'EVP_BytesToKey',
        'PKCS5_PBKDF2_HMAC',
        'PKCS5_PBKDF2_HMAC_SHA1',
        'EVP_MD5',
        'EVP_sha1',
        'EVP_sha256',
        'MD5',
        'SHA1',
        'SHA256',
        'RAND_bytes',
        'RAND_pseudo_bytes',
        'AES_set_encrypt_key',
        'AES_set_decrypt_key',
        'AES_encrypt',
        'AES_decrypt'
    ];
    
    functions_to_hook.forEach(function(func_name) {
        try {
            var func_addr = libcrypto.getExportByName(func_name);
            if (func_addr) {
                console.log("[+] Hooking " + func_name + " at " + func_addr);
                
                Interceptor.attach(func_addr, {
                    onEnter: function(args) {
                        console.log("\\n[!] " + func_name + " called!");
                        console.log("    Address: " + this.returnAddress);
                        console.log("    Thread: " + this.threadId);
                        
                        // Store function name for onLeave
                        this.func_name = func_name;
                        
                        // Special handling for key derivation functions
                        if (func_name === 'RAND_bytes' || func_name === 'RAND_pseudo_bytes') {
                            console.log("    Buffer: " + args[0]);
                            console.log("    Length: " + args[1]);
                            this.buffer = args[0];
                            this.length = args[1].toInt32();
                        }
                        else if (func_name === 'EVP_BytesToKey') {
                            console.log("    Type: " + args[0]);
                            console.log("    MD: " + args[1]);
                            console.log("    Salt: " + args[2]);
                            console.log("    Data: " + args[3]);
                            console.log("    Data_len: " + args[4]);
                            console.log("    Count: " + args[5]);
                            console.log("    Key buffer: " + args[6]);
                            console.log("    IV buffer: " + args[7]);
                        }
                        else if (func_name.startsWith('EVP_') && func_name.includes('Init')) {
                            console.log("    Context: " + args[0]);
                            console.log("    Cipher/Type: " + args[1]);
                            if (args[2] && !args[2].isNull()) {
                                console.log("    Key: " + args[2]);
                                try {
                                    console.log("    Key data (32 bytes): " + hexdump(args[2], {length: 32, ansi: false}));
                                } catch(e) {}
                            }
                            if (args[3] && !args[3].isNull()) {
                                console.log("    IV: " + args[3]);
                                try {
                                    console.log("    IV data (16 bytes): " + hexdump(args[3], {length: 16, ansi: false}));
                                } catch(e) {}
                            }
                        }
                        else if (func_name === 'PKCS5_PBKDF2_HMAC' || func_name === 'PKCS5_PBKDF2_HMAC_SHA1') {
                            console.log("    Password: " + args[0]);
                            console.log("    Password_len: " + args[1]);
                            console.log("    Salt: " + args[2]);
                            console.log("    Salt_len: " + args[3]);
                            console.log("    Iterations: " + args[4]);
                            console.log("    Key_len: " + args[5]);
                            console.log("    Out: " + args[6]);
                            this.out_buffer = args[6];
                            this.out_length = args[5].toInt32();
                        }
                    },
                    onLeave: function(retval) {
                        // Show generated random bytes or keys
                        if ((this.func_name === 'RAND_bytes' || this.func_name === 'RAND_pseudo_bytes') && this.buffer && this.length) {
                            try {
                                console.log("    Generated random bytes:");
                                console.log(hexdump(this.buffer, {length: Math.min(this.length, 256), ansi: false}));
                            } catch(e) {
                                console.log("    [Error reading buffer]");
                            }
                        }
                        else if ((this.func_name === 'PKCS5_PBKDF2_HMAC' || this.func_name === 'PKCS5_PBKDF2_HMAC_SHA1') && this.out_buffer && this.out_length) {
                            try {
                                console.log("    Derived key:");
                                console.log(hexdump(this.out_buffer, {length: Math.min(this.out_length, 256), ansi: false}));
                            } catch(e) {
                                console.log("    [Error reading buffer]");
                            }
                        }
                        
                        console.log("    Return: " + retval);
                    }
                });
            }
        } catch(e) {
            // Function not found, skip
        }
    });
}

console.log("[*] OpenSSL hooks installed. Waiting for crypto operations...");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] {message['stack']}")

def main():
    print("[*] Attaching to Engine DJ...")
    
    try:
        # Attach to Engine DJ process
        session = frida.attach("Engine DJ.exe")
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!")
        print("[!] Please start Engine DJ first")
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
