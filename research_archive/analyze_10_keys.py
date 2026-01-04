#!/usr/bin/env python3
"""
Analyze the 10 extracted keys to find derivation pattern.
Keys extracted from FFmpeg packets during stem file creation.
"""

import hashlib

keys_hex = [
    "3a81b058700c860ed3b8efe2dfb07b61d0aef39e40436329087d780909972900 5a5465f48506" 
    "41cb6118fcd9 80e26868194b7b633f142ae78ab9de2a60df3a04c41949efe6de0a9165 6dede526ffa72fa071a083c693305 7 71c2fa3c69fc6c9dd44 3f9a77e89c5373f3c9fde8e2ff3f464f916af520f6ce6b2c7786 06fab9c32732",
    
    "5d077ad9cd3936d0c958a90508 8b39f044f68b3a1bd4079 5b3ca5ff86 9a0a24 6f6da9d5358 4b987f92387 71f1b861c d72fff8f93756 9cae9053 34c552fcc4056 0975 5a56c9b18d5c52b9f76606390b4f74e1 8c11988 8e2c848cf69 02c0 8616dc84d00b8 ad7d92 6c412 0cc7a14eca01939 11fa2b7ea33e846148861197 32ff795d",
    
    "1209f67e1b1a003e00ffd9a74a1208 e6e04db2 42d08a a4 8c4f7 116 73e73de91 2 7c0f25 150c34b0614d59e289 a0dfd4e32dfd0366e779 49aeb4c5897a02486d68d2e8340e5ac5de88d0 e9bf5cb9c65dd03cdf92f7c107d57 888d5e46 e2a5cb83 aba2aecf05 97aaee15eb 10096f867f0bc33ba6a5cde34a1b7421 6a8f768 c5fc652",
    
    "9ffa55d49f19be595d07cfdb619d8d223ef893 77ce73c416fe387b0c3b4fb206e7 ae8edcc3 31ff657 03cde75a04a2cca20f146 0666ad75b2c591175dc51efb86cdff80501759 a191ab797 a078f25f4e88 7786ce 7162e60afc d07e7901f48 591b054ed75a02414fa378 e60ccf220fb7556 4c963 03bb54cdc7d 66ab00 5674 3c9dff",
    
    "69dda9d2bb5229b34164b52fb6f12bd41ff213ddee16b22 3 04f98094f8cf32c24f6b7f1772 1761cda875d10900719bcc347cbabbae324744 09ac7a9f261 5 4a4c9f408 081 19cd86b1272 3462657 008 3843ba132 1d185baab5bbca807c23c2d44 2822566c545343f29c116 7406fe91 4ff68f2ae5d80109544336 1 02b41e6f3880 7c",
    
    "eccb9edfafacf3ac1060799 5acba0d00953693e3fde7ed64c79adbba3d046b13d006a40d1b0b46749 b2488 3c8161ba2cb20b4f10ededad1bf2d75e58b9840e71e044f0e716 57e3e37f7fccf5 8f728f0f1c316 7729fe3 a493aa3d18f6f8d9b53caabc ab24805f132b0357738b734 316 0ec93e9657fc dcafd487 9ac5d031b070",
    
    "ef23613edb7a8488ab72992 2a6b58fbdb76f1 3332856 880e886d5ee1b0e8e951b9a3b7eb23c3f886 eeb9e6b6 bdd62c71 edf37e7bd473 0a7513d56e6fcafca78bec0ac74c49 7380 0f1f8ce4c93cee76 602 25 5c25a496535c5f2d96394 ecacb224 4f c69ecc154fe217 71b3621cf6 0b3db6412171047ff01 200 96ef1825cbdc33bf07",
    
    "fd3210da84138bc734bf9c4cab01a7bda7043c6812729e8c05 6bb93bc9bb9d 0c80 bfad96ab334 3ed8349d106 aca05f1fc197baf307704b3330c3602 a0f268eaf2778fe8e183b4e9bd0e6901d8a69 28a930112301 8a42bfb20976 5a285 306fdbd4ae8ee77defe f6cc2af41985 7ca7aa36adc775d7cf8a7626 1e8a013ecfd2a02a",
    
    "e6c37f67091c48a73312cafa1b28e3419b681 03336fe7e07799938 51d8344acced46ec5aca33 73d9a3c25b894 68b5e286 4c1b7d365851 3e1caf d08cd4f6870c 0aca521ceb7ccd74 71c82 4bebcc065de706e276 0006 39d6d59ceaea8e5569ac40c317dce32daa0ba3cbed9868e6d 7acd4ef8eed61 cff42 72e08c47d83f1 aadc a2fb6d",
    
    "717331 17e864710ce2f308c4b2047f62a4c4974b69 67a92d7ad92a8e2e1f765 86ca36e8a 0c6e38083af 648c0b0335dc95da5d6a8d865f6de5b0c13d004ab51b2faba c80eaaa7dcd6 0103560 0d122fb 585 7bfca7274 51e6b1c9ecd7 7998e903 6be01 5c399c76 6e0 891bf391 f0a3def828 7c6fce14afbec95a91097 b61b7c9d352"
]

# Clean up hex strings (remove spaces)
keys_hex = [k.replace(" ", "") for k in keys_hex]

print("=" * 80)
print("KEY DERIVATION ANALYSIS - 10 Extracted Keys")
print("=" * 80)

# Convert to bytes
keys = [bytes.fromhex(k) for k in keys_hex]

print(f"\n[*] Analyzing {len(keys)} keys, each {len(keys[0])} bytes\n")

# Try common hash-based derivation patterns
# Pattern 1: key[n] = MD5(uuid + n)
# Pattern 2: key[n] = SHA256(uuid + n)
# Pattern 3: key[n] = MD5(base_key + n)

print("[*] Testing hash-based derivation patterns...\n")

# Test if key[1] could be MD5(something)
key1 = keys[0][:16]  # First 16 bytes = potential MD5
print(f"Key 1 (first 16 bytes): {key1.hex()}")

# Try hashing frame indices
for frame_idx in range(10):
    # Try MD5(frame_index as bytes)
    test_input = bytes([frame_idx])
    md5_hash = hashlib.md5(test_input).digest()
    if md5_hash == key1:
        print(f"  ✓ MATCH: MD5({frame_idx}) = {key1.hex()}")

# Try with different seeds
uuid_str = "0f7da717-a4c6-46be-994e-eca19516836c"  # From filename
uuid_bytes = uuid_str.encode()

print(f"\nTesting with UUID: {uuid_str}")

# Test MD5(UUID + frame_index)
for frame_idx in range(10):
    test_data = uuid_bytes + bytes([frame_idx])
    md5_hash = hashlib.md5(test_data).digest()
    print(f"Frame {frame_idx}: MD5(UUID+{frame_idx}) = {md5_hash.hex()}")
    
    if md5_hash == key1:
        print(f"  ✓✓✓ MATCH for Frame 1!")

print("\n[*] Checking if keys increment by constant value...\n")

# Check XOR differences between consecutive keys
xor_diffs = []
for i in range(len(keys) - 1):
    xor_diff = bytes(a ^ b for a, b in zip(keys[i][:16], keys[i+1][:16]))
    xor_diffs.append(xor_diff)
    print(f"Key[{i+1}] XOR Key[{i}] (first 16 bytes): {xor_diff.hex()}")

# Check if all XOR diffs are identical
if len(set(str(x) for x in xor_diffs)) == 1:
    print("\n✓ All XOR differences are IDENTICAL - simple stream cipher!")
else:
    print("\n✗ XOR differences vary - likely hash-based or PRNG")

print("\n" + "=" * 80)
