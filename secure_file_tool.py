import os
import argparse
import gzip
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Dictionary to track decryption attempts per file
decryption_attempts = {}
ATTEMPT_LIMIT = 5
LOCKOUT_TIME = 300  # in seconds

def derive_key(password, salt, iterations=100000):
    """Derives a secure key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_hmac(key, data):
    """Generates an HMAC for integrity verification."""
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(data)
    return hmac.finalize()

def verify_hmac(key, data, expected_hmac):
    """Verifies the HMAC for integrity."""
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(data)
    try:
        hmac.verify(expected_hmac)
        return True
    except Exception:
        return False

def compress_data(data):
    """Compresses data using gzip."""
    return gzip.compress(data)

def decompress_data(data):
    """Decompresses gzip-compressed data."""
    return gzip.decompress(data)

def encrypt_file(file_path, password, output_path):
    """Encrypts a file using AES-256 and includes HMAC for integrity."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    compressed_plaintext = compress_data(plaintext)
    ciphertext = encryptor.update(compressed_plaintext) + encryptor.finalize()
    hmac = generate_hmac(key, ciphertext)

    with open(output_path, 'wb') as f:
        f.write(salt + iv + hmac + ciphertext)

def decrypt_file(file_path, password, output_path):
    """Decrypts a file using AES-256 and verifies HMAC for integrity."""
    # Track decryption attempts
    current_time = time.time()
    if file_path in decryption_attempts:
        attempts, lockout_start = decryption_attempts[file_path]
        if attempts >= ATTEMPT_LIMIT:
            if current_time - lockout_start < LOCKOUT_TIME:
                raise ValueError("Too many failed attempts. Please try again later.")
            else:
                # Reset attempts after lockout period
                decryption_attempts[file_path] = [0, 0]
    else:
        decryption_attempts[file_path] = [0, 0]

    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    hmac = data[32:64]
    ciphertext = data[64:]

    key = derive_key(password, salt)
    if not verify_hmac(key, ciphertext, hmac):
        # Increment failed attempts
        decryption_attempts[file_path][0] += 1
        decryption_attempts[file_path][1] = current_time
        raise ValueError("HMAC verification failed. File integrity compromised.")

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    compressed_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = decompress_data(compressed_plaintext)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    # Reset attempts on success
    decryption_attempts[file_path] = [0, 0]

def main():
    """Command-line interface for the encryption tool."""
    parser = argparse.ArgumentParser(description="Secure File Encryption and Decryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser.add_argument("file", help="Path to the input file")
    parser.add_argument("password", help="Password for encryption/decryption")
    parser.add_argument("output", help="Path to save the output file")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.file, args.password, args.output)
        print(f"File encrypted successfully and saved to {args.output}")
    elif args.mode == "decrypt":
        try:
            decrypt_file(args.file, args.password, args.output)
            print(f"File decrypted successfully and saved to {args.output}")
        except ValueError as e:
            print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
