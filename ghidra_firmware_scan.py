#@category Firmware/Analysis
"""
Ghidra helper script for STM32F4 firmware triage.
Runs two passes in one file to keep reuse:
  1) find_dwords: locate interesting constants (frame sizes, seed, MP4 atoms, crypto bases).
  2) find_ascii_tokens: locate ASCII tokens relevant to MP4/stems.

Usage: Load firmware in Ghidra, then run this script from Script Manager.
Adjust the constant lists below as needed.
"""

from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
mem = currentProgram.getMemory()

# ----------------------------------------
# Helpers
# ----------------------------------------

def dword_to_le_hex(val):
    """Return space-separated hex string for findBytes (little endian)."""
    b0 = val & 0xff
    b1 = (val >> 8) & 0xff
    b2 = (val >> 16) & 0xff
    b3 = (val >> 24) & 0xff
    return "%02X %02X %02X %02X" % (b0, b1, b2, b3)


def find_bytes(pattern_hex, label):
    """Find all occurrences of a byte pattern (hex string) and print addresses."""
    start = currentProgram.getMinAddress()
    addrs = []
    addr = mem.findBytes(start, pattern_hex, None, True, monitor)
    while addr is not None:
        addrs.append(addr)
        next_addr = addr.add(1)
        addr = mem.findBytes(next_addr, pattern_hex, None, True, monitor)
    if addrs:
        println("[+] %s (%s):" % (label, pattern_hex))
        for a in addrs:
            println("    %s" % a)
    else:
        println("[-] %s: not found" % label)


def find_dwords(constants, label):
    println("\n=== Searching dwords: %s ===" % label)
    for name, val in constants:
        pattern_hex = dword_to_le_hex(val)
        find_bytes(pattern_hex, "%s = 0x%X" % (name, val & 0xFFFFFFFF))


def find_ascii_tokens(tokens, label):
    println("\n=== Searching ASCII tokens: %s ===" % label)
    for tok in tokens:
        hexpat = " ".join(["%02X" % ord(ch) for ch in tok])
        find_bytes(hexpat, "\"%s\"" % tok)

# ----------------------------------------
# Configurable search sets
# ----------------------------------------

FRAME_CONSTANTS = [
    ("FRAME_SIZE_1648", 0x670),
    ("ENCRYPTED_SIZE_1520", 0x5F0),
    ("KEY_SIZE_128", 0x80),
    ("AAC_SYNC_0xFFF", 0xFFF),
]

SEED_CONSTANTS = [
    ("KNOWN_SEED", 0xE485B014),
]

MP4_ATOMS = [
    ("ATOM_mdat", 0x6D646174),  # "mdat" little-endian dword
    ("ATOM_moov", 0x766F6F6D),  # "moov"
    ("ATOM_ftyp", 0x70797466),  # "ftyp" (note: reversed order for LE search)
]

CRYPTO_MMIO = [
    ("CRYP_BASE", 0x50060000),
    ("HASH_BASE", 0x50060400),
    ("RNG_BASE", 0x50060800),
    ("CRC_BASE", 0x40023000),
    ("RCC_BASE", 0x40023800),
]

ASCII_TOKENS = [
    "ftyp", "moov", "mdat", "stco", "stsz", "mp4a", "aac", "uuid", "seed",
    "stems", "decrypt", "encrypt", "key", "frame"
]

# ----------------------------------------
# Execute searches
# ----------------------------------------

find_dwords(FRAME_CONSTANTS + SEED_CONSTANTS + MP4_ATOMS + CRYPTO_MMIO, "constants")
find_ascii_tokens(ASCII_TOKENS, "strings")

println("\nDone. Review hits and cross-reference to functions for candidate decrypt paths.")
