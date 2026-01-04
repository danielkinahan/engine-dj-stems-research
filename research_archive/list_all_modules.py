import frida
import sys

script_code = """
console.log("[*] Enumerating all loaded modules...");
console.log("");

Process.enumerateModules().forEach(function(module) {
    var name_lower = module.name.toLowerCase();
    // Show all modules that might be crypto-related
    if (name_lower.includes('crypto') || 
        name_lower.includes('ssl') || 
        name_lower.includes('crypt') ||
        name_lower.includes('cipher') ||
        name_lower.includes('aes') ||
        name_lower.includes('bcrypt')) {
        console.log("[+] " + module.name);
        console.log("    Base: " + module.base);
        console.log("    Size: " + module.size);
        console.log("    Path: " + module.path);
        console.log("");
    }
});

console.log("[*] Done");
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])

def main():
    try:
        session = frida.attach("Engine DJ.exe")
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        input()  # Keep script alive
    except frida.ProcessNotFoundError:
        print("[!] Engine DJ not running!")

if __name__ == '__main__':
    main()
