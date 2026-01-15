#!/usr/bin/env python3
"""
Decrypt Engine DJ .stems files using AES-128-CBC

Algorithm discovered from controller firmware analysis:
- Cipher: AES-128-CBC (OpenSSL EVP)
- Frame size: 1648 bytes (128-byte IV header + 1520-byte encrypted AAC)
- Key: 16 bytes (to be found)
"""

import struct
import sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class StemsDecryptor:
    """Decrypt Engine DJ stems files"""
    
    def __init__(self, stems_file):
        self.stems_file = Path(stems_file)
        self.data = self.stems_file.read_bytes()
        self.key = None
        self.frames = []
        
    def parse_mp4_atoms(self):
        """Parse MP4 atom structure to find key and mdat"""
        pos = 0
        atoms = {}
        
        print("[*] Parsing MP4 structure...")
        while pos < len(self.data):
            if pos + 8 > len(self.data):
                break
                
            size = struct.unpack('>I', self.data[pos:pos+4])[0]
            atom_type = self.data[pos+4:pos+8].decode('ascii', errors='ignore')
            
            if size == 0:
                size = len(self.data) - pos
            if size < 8:
                break
                
            atom_data = self.data[pos+8:pos+size]
            atoms[atom_type] = {
                'offset': pos,
                'size': size,
                'data': atom_data,
                'pos': pos
            }
            
            print(f"  Found atom: {atom_type} at 0x{pos:08x}, size: {size} bytes")
            
            # Look for keys in custom atoms
            if atom_type.startswith('s') or atom_type in ['senc', 'uuid', 'enca']:
                print(f"    -> Possible key atom: {atom_type}")
                # Check if first 16 bytes look like a key (16 bytes, fairly random)
                if len(atom_data) >= 16:
                    potential_key = atom_data[:16]
                    if self._looks_like_key(potential_key):
                        print(f"    -> Potential AES key found: {potential_key.hex()}")
                        self.key = potential_key
            
            pos += size
            
        return atoms
    
    def _looks_like_key(self, data):
        """Simple heuristic: key should have decent entropy and no long repeated patterns"""
        if len(data) != 16:
            return False
        # Reject if all zeros or all same byte
        if len(set(data)) < 4:
            return False
        return True
    
    def find_mdat(self):
        """Find mdat atom containing encrypted frames"""
        pos = 0
        while pos < len(self.data):
            if pos + 8 > len(self.data):
                break
            size = struct.unpack('>I', self.data[pos:pos+4])[0]
            atom_type = self.data[pos+4:pos+8]
            
            if size == 0:
                size = len(self.data) - pos
            if size < 8:
                break
            
            if atom_type == b'mdat':
                print(f"[+] Found mdat at 0x{pos:08x}, size: {size} bytes")
                return pos + 8, size - 8  # Skip mdat header
            
            pos += size
        return None, None
    
    def try_decrypt_frame(self, encrypted_frame, key, iv):
        """Try to decrypt a frame and check for AAC sync pattern"""
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_frame)
            
            # Try to unpad (PKCS7)
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except:
                pass  # Not padded or padding failed, use as-is
            
            # Check for AAC sync word (0xFFF at start of each frame)
            # AAC ADTS sync: first 12 bits are 1 (0xFFF)
            if len(decrypted) >= 2:
                sync = (decrypted[0] << 4) | (decrypted[1] >> 4)
                if sync == 0xFFF:
                    print(f"[+] Found AAC sync word! Key is likely correct.")
                    return True, decrypted
            
            return False, decrypted
        except Exception as e:
            return False, None
    
    def brute_force_key(self):
        """Try to find the correct key by decrypting first frame"""
        mdat_pos, mdat_size = self.find_mdat()
        if mdat_pos is None:
            print("[!] No mdat atom found")
            return False
        
        # Extract first frame (1648 bytes = 128 IV + 1520 encrypted)
        frame_pos = mdat_pos
        if frame_pos + 1648 > len(self.data):
            print("[!] Not enough data for first frame")
            return False
        
        frame_data = self.data[frame_pos:frame_pos + 1648]
        iv = frame_data[:16]
        encrypted = frame_data[16:1536]  # 1520 bytes
        
        print(f"\n[*] First frame IV: {iv.hex()}")
        print(f"[*] Encrypted payload: {len(encrypted)} bytes")
        
        # Try keys from MP4 atoms
        print("\n[*] Trying keys found in MP4 atoms...")
        if self.key:
            success, decrypted = self.try_decrypt_frame(encrypted, self.key, iv)
            if success:
                print(f"[+] Success with key: {self.key.hex()}")
                return True
            else:
                print(f"[-] Key {self.key.hex()} didn't produce AAC")
        
        # Try common defaults
        print("\n[*] Trying common default keys...")
        test_keys = [
            bytes(16),  # All zeros
            b'\x00' * 16,
            bytes.fromhex('00' * 16),
        ]
        
        for test_key in test_keys:
            success, decrypted = self.try_decrypt_frame(encrypted, test_key, iv)
            if success:
                self.key = test_key
                print(f"[+] Success with key: {test_key.hex()}")
                return True
        
        print("[-] No valid key found with default attempts")
        return False
    
    def decrypt_all_frames(self):
        """Decrypt all frames in the mdat"""
        if self.key is None:
            print("[!] No key available")
            return []
        
        mdat_pos, mdat_size = self.find_mdat()
        if mdat_pos is None:
            return []
        
        decrypted_frames = []
        pos = mdat_pos
        frame_num = 0
        
        print(f"\n[*] Decrypting frames with key: {self.key.hex()}")
        
        while pos + 1648 <= len(self.data):
            frame_data = self.data[pos:pos + 1648]
            iv = frame_data[:16]
            encrypted = frame_data[16:1536]
            
            try:
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                decrypted_frames.append(decrypted)
                
                if frame_num < 3:
                    print(f"  Frame {frame_num}: IV={iv[:8].hex()}..., decrypted {len(decrypted)} bytes")
                
                frame_num += 1
            except Exception as e:
                print(f"[!] Error decrypting frame {frame_num}: {e}")
                break
            
            pos += 1648
        
        print(f"[+] Decrypted {len(decrypted_frames)} frames")
        return decrypted_frames
    
    def save_decrypted(self, output_file, decrypted_frames):
        """Save decrypted frames to output file"""
        with open(output_file, 'wb') as f:
            for frame in decrypted_frames:
                f.write(frame)
        print(f"[+] Saved decrypted audio to {output_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt_stems_aes_cbc.py <stems_file> [output_file]")
        sys.exit(1)
    
    stems_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "decrypted.aac"
    
    print(f"[*] Opening {stems_file}...")
    decryptor = StemsDecryptor(stems_file)
    
    # Parse MP4 to find key
    atoms = decryptor.parse_mp4_atoms()
    
    # Try to find/brute-force the key
    if decryptor.brute_force_key():
        # Decrypt all frames
        decrypted_frames = decryptor.decrypt_all_frames()
        
        if decrypted_frames:
            decryptor.save_decrypted(output_file, decrypted_frames)
            print(f"\n[+] Decryption complete!")
            print(f"    Key: {decryptor.key.hex()}")
            print(f"    Output: {output_file}")
    else:
        print("[!] Could not find valid decryption key")


if __name__ == '__main__':
    main()
