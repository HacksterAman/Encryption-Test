from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path
import os
from concurrent.futures import ThreadPoolExecutor

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB

def generate_key():
    # Generate a 256-bit AES key
    return get_random_bytes(32)

def encrypt_chunk(cipher, chunk):
    # Encrypt a single chunk
    return cipher.encrypt(chunk)

def decrypt_chunk(cipher, chunk):
    # Decrypt a single chunk
    return cipher.decrypt(chunk)

def encrypt_file(path):
    try:
        key = generate_key()
        cipher = AES.new(key, AES.MODE_GCM)
        iv = cipher.nonce
        _path = str(Path(path).with_suffix(''))
       
        with open(path, 'rb') as infile, open(path + ".v", 'wb') as outfile:
            with ThreadPoolExecutor() as executor:
                # Encrypt file in chunks
                while chunk := infile.read(CHUNK_SIZE):
                    encrypted_chunk = executor.submit(encrypt_chunk, cipher, chunk).result()
                    outfile.write(encrypted_chunk)

            # Finalize and save the authentication tag
            tag = cipher.digest()
            with open(_path + ".tag", 'wb') as f:
                f.write(tag)
        
        # Save key and IV
        with open(_path + ".key", 'wb') as f:
            f.write(key)
        with open(_path + ".iv", 'wb') as f:
            f.write(iv)

        print(f"File encrypted successfully: {path + ".v"}")
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file(path):
    try:
        _path = str(Path(str(Path(path).with_suffix(''))).with_suffix(''))

        # Load key, IV, and tag
        with open(_path + ".key", 'rb') as f:
            key = f.read()
        with open(_path + ".iv", 'rb') as f:
            iv = f.read()
        with open(_path + ".tag", 'rb') as f:
            tag = f.read()

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        with open(path, 'rb') as infile, open(str(Path(path).with_suffix('')), 'wb') as outfile:
            with ThreadPoolExecutor() as executor:
                # Decrypt file in chunks
                while chunk := infile.read(CHUNK_SIZE):
                    decrypted_chunk = executor.submit(decrypt_chunk, cipher, chunk).result()
                    outfile.write(decrypted_chunk)

            # Verify the authentication tag
            cipher.verify(tag)

        print(f"File decrypted successfully: {path}")
    except ValueError as e:
        print("Error: Authentication failed. Possible tampered file or incorrect key/IV.")
    except Exception as e:
        print(f"Error during decryption: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AES-256-GCM File Encryptor/Decryptor with Chunk Processing")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("path", help="Path to the input file")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.path)
    elif args.mode == "decrypt":
        decrypt_file(args.path)
