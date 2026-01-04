#!/usr/bin/env python3
"""
Compare frame 1 and frame 2 keys to find the pattern.
"""

# Frame 1 - Unencrypted
frame1_unenc = bytes.fromhex("""
de 04 00 4c 61 76 63 35 38 2e 31 33 34 2e 31 30
30 00 42 36 07 ea 8b 25 1a 23 41 33 ed f1 ce 7b
71 cf 1b d7 73 57 ab 94 85 55 94 00 a0 1c 6b 90
43 7b 2f 1f db fd ce 4a 33 e8 f3 fe 51 e4 2d 9c
b1 ef c1 ef 7b 1e 55 e8 8c 53 2d 55 09 8b df fb
1d ee 71 63 ae 51 ae 4d ad a7 ea f3 db c4 98 c7
09 46 fd 60 78 a7 a6 56 09 d9 2d c6 3b ff d4 45
bb f6 f8 98 02 2c 24 44 e1 01 11 01 06 22 19 a8
""".replace('\n', '').replace(' ', ''))

# Frame 1 - Encrypted (from WriteFile #2469 offset 0)
frame1_enc = bytes.fromhex("""
e4 85 b0 14 11 7a e5 3b eb 96 de d1 eb 9e 4a 51
32 74 ce f5 4d 12 eb 6b 34 28 35 b2 b2 e2 90 17
7d 7e 43 93 7c c5 c7 6e a0 92 1b 16 be 26 a8 d1
ee 9e 1a df 58 e1 38 cc 2b 11 a4 2d 5e e4 2e 7d
f4 12 60 d1 f7 a3 e8 74 1f 7e a5 7c 60 e6 f7 99
6a ee 89 76 56 ce d8 cb 98 bf 78 17 ea e5 31 f2
5b 28 bf 5e 03 c9 16 e5 5b 44 7b 3c ed 50 12 d5
7a dd 55 3b 52 dc ef ab 57 c5 5e f9 9f ee 8e 91
""".replace('\n', '').replace(' ', ''))

# Frame 2 - Unencrypted (from Packet #2)
frame2_unenc = bytes.fromhex("""
21 1b 04 05 aa 16 83 61 10 cd ef e3 03 db d7 9e
7a e7 53 8d 79 bd b4 66 70 14 0a 28 a0 54 64 66
5c ca e3 b4 13 44 0e 21 18 62 0c 11 0c a3 0e e7
18 93 a5 3f d2 da cb 20 54 6e c9 8a 49 c5 08 60
7d 61 0a 45 0e f2 8b 59 a1 78 9e c6 34 4d 6c b1
50 1f 17 8e ce 42 9c eb ef 97 0c 25 d3 18 b9 dd
7a 08 da 1c 61 55 ec 63 a1 88 59 a7 04 e4 4d 34
d6 dd bc e9 96 b7 01 35 b5 3a 69 d1 ed 24 69 5a
""".replace('\n', '').replace(' ', ''))

# Frame 2 - Encrypted (from WriteFile, need to get offset 1520 from the 262144-byte write)
# For now, I'll ask user to find it, but let's see if we can infer the key pattern

key1 = bytes(u ^ e for u, e in zip(frame1_unenc, frame1_enc))
print("="*70)
print("FRAME 1 XOR KEY")
print("="*70)
for i in range(0, min(64, len(key1)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in key1[i:i+16])
    print(f"  {i:04x}: {hex_part}")

print("\nNeed Frame 2 encrypted data to continue...")
print("Frame 2 should start at offset 1520 (0x5F0) in the 262144-byte WriteFile")
print("\nLooking at stems_capture.txt, find:")
print("  [WriteFile #2469] Writing 262144 bytes")
print("Then go to line showing offset 0x5F0")
