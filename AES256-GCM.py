from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pathlib import Path

def generate_key():
    #Generate a 256-bit AES key
    return get_random_bytes(32)


def encrypt_file(path):
    try:
        # Encryption
        key = generate_key()
        cipher = AES.new(key, AES.MODE_GCM, use_aesni='True')
        iv = cipher.nonce

        # Read the input file data
        with open(path, 'rb') as f:
            plaintext = f.read()

        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Save encrypted data
        with open(path + ".v", 'wb') as f:
            f.write(ciphertext)

        # Save key, IV, and authentication tag to separate binary files
        _path = str(Path(path).with_suffix(''))
        with open(_path + ".key", 'wb') as f:
            f.write(key)
        with open(_path + ".iv", 'wb') as f:
            f.write(iv)
        with open(_path + ".tag", 'wb') as f:
            f.write(tag)
        
        print(f"File encrypted successfully: {path}")
    except Exception as e:
        print(f"Error during encryption: {e}")


def decrypt_file(path):
    try:
        # Read ciphertext from the input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
      
        # Load key, IV, and authentication tag from files
        _path = str(Path(path).with_suffix(''))
        with open(_path + ".key", 'rb') as f:
            key = f.read()
        with open(_path + ".iv", 'rb') as f:
            iv = f.read()
        with open(_path + ".tag", 'rb') as f:
            tag = f.read()
                      
        # Decryption
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv, use_aesni='True')
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
        # Save the decrypted data
        with open(path, 'wb') as f:
            f.write(plaintext)
        
        print(f"File decrypted successfully: {path}")
    except InvalidTag:
        print("Error: Authentication failed. Possible incorrect key/IV/auth tag.")
    except Exception as e:
        print(f"Error during decryption: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AES-256-GCM File Encryptor/Decryptor with Separate Files")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode of operation")
    parser.add_argument("path", help="Path to the input file")
    args = parser.parse_args()

    if args.mode == "encrypt":
        encrypt_file(args.path)
    elif args.mode == "decrypt":
        decrypt_file(args.path)
