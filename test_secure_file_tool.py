import unittest
import os
import time
from secure_file_tool import encrypt_file, decrypt_file, derive_key, compress_data, decompress_data

class TestSecureFileTool(unittest.TestCase):
    test_file = "test.txt"
    encrypted_file = "test_encrypted.bin"
    decrypted_file = "test_decrypted.txt"
    password = "securepassword"

    def setUp(self):
        """Set up a test file."""
        with open(self.test_file, 'w') as f:
            f.write("This is a test file for encryption and decryption.")

    def tearDown(self):
        """Clean up test files."""
        for file in [self.test_file, self.encrypted_file, self.decrypted_file]:
            if os.path.exists(file):
                os.remove(file)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption functionality."""
        encrypt_file(self.test_file, self.password, self.encrypted_file)
        decrypt_file(self.encrypted_file, self.password, self.decrypted_file)

        with open(self.test_file, 'r') as original, open(self.decrypted_file, 'r') as decrypted:
            self.assertEqual(original.read(), decrypted.read(), "Decrypted file does not match the original.")

    def test_hmac_integrity(self):
        """Test file tampering detection."""
        encrypt_file(self.test_file, self.password, self.encrypted_file)

        # Tamper with the encrypted file
        with open(self.encrypted_file, 'rb') as f:
            data = bytearray(f.read())
        data[-1] ^= 0xFF  # Flip the last bit
        with open(self.encrypted_file, 'wb') as f:
            f.write(data)

        with self.assertRaises(ValueError, msg="HMAC verification failed. File integrity compromised."):
            decrypt_file(self.encrypted_file, self.password, self.decrypted_file)

    def test_compression_decompression(self):
        """Test compression and decompression functionality."""
        original_data = b"This is some test data to compress and decompress."
        compressed_data = compress_data(original_data)
        decompressed_data = decompress_data(compressed_data)
        self.assertEqual(original_data, decompressed_data, "Decompressed data does not match the original.")

    def test_brute_force_defense(self):
        """Test lockout after multiple failed decryption attempts."""
        encrypt_file(self.test_file, self.password, self.encrypted_file)

        for _ in range(5):
            with self.assertRaises(ValueError, msg="HMAC verification failed. File integrity compromised."):
                decrypt_file(self.encrypted_file, "wrongpassword", self.decrypted_file)

        # 6th attempt should trigger lockout
        with self.assertRaises(ValueError, msg="Too many failed attempts. Please try again later."):
            decrypt_file(self.encrypted_file, "wrongpassword", self.decrypted_file)

        # Wait for lockout to expire and then decrypt with the correct password
        time.sleep(300)
        decrypt_file(self.encrypted_file, self.password, self.decrypted_file)
        with open(self.test_file, 'r') as original, open(self.decrypted_file, 'r') as decrypted:
            self.assertEqual(original.read(), decrypted.read(), "Decrypted file does not match the original after lockout reset.")

if __name__ == "__main__":
    unittest.main()
