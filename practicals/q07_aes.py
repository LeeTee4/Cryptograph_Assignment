"""Q7: AES encryption and decryption.

AES (Advanced Encryption Standard) is a symmetric block cipher: the same secret
key is used to encrypt and to decrypt. It replaced DES and is the current standard.

- Key size:   128, 192 or 256 bits (16, 24 or 32 bytes). The default here is 256 bits.
- Block size: always 128 bits (16 bytes), whatever the key size.
- Rounds:     10 rounds for a 128-bit key, 12 for 192-bit and 14 for 256-bit.
- Mode:       GCM (Galois/Counter Mode) with a random 12-byte nonce.
- Padding:    none. GCM works like a stream cipher, so the ciphertext is the same
              length as the plaintext.

GCM is authenticated encryption: as well as hiding the message, it produces a
16-byte authentication tag. If anyone changes the ciphertext, the tag check fails
on decryption, so tampering is detected.

Never reuse a nonce with the same key in GCM. Here a fresh random nonce is made
for every message.
"""

import argparse
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

DEFAULT_TEXT = "I am coming tonight"

# Number of AES rounds for each key size, used only for printing.
ROUNDS = {128: 10, 192: 12, 256: 14}


def generate_key(key_size_bits=256):
    """Create a random AES key of 128, 192 or 256 bits."""
    return get_random_bytes(key_size_bits // 8)


def encrypt(key, text):
    """Encrypt text with AES-GCM and return (nonce, ciphertext, tag)."""
    # Step 1: make a fresh random 12-byte nonce (the recommended size for GCM).
    nonce = get_random_bytes(12)

    # Step 2: set up an AES cipher in GCM mode with our key and nonce.
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Step 3: encrypt the text and compute the authentication tag in one go.
    ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))

    # The nonce and tag are not secret. They are sent along with the ciphertext.
    return nonce, ciphertext, tag


def decrypt(key, nonce, ciphertext, tag):
    """Decrypt AES-GCM ciphertext and check the tag. Raises ValueError if it was tampered with."""
    # Step 1: set up the same AES-GCM cipher with the same key and nonce.
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Step 2: decrypt and verify the tag together. pycryptodome raises
    # ValueError if the tag does not match, meaning the data was changed
    # or the wrong key was used.
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Authentication failed: the tag does not match, "
                         "so the ciphertext was tampered with or the key is wrong.")

    # Step 3: turn the bytes back into text.
    return plaintext.decode("utf-8")


def flip_one_byte(data, position=0):
    """Return a copy of data with one byte changed, to simulate an attacker."""
    tampered = bytearray(data)
    tampered[position] ^= 0x01  # flip the lowest bit of that byte
    return bytes(tampered)


def main():
    # Read optional text and key size from the command line.
    parser = argparse.ArgumentParser(description="AES-GCM encryption and decryption.")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to encrypt")
    parser.add_argument("--key-size", type=int, choices=[128, 192, 256], default=256,
                        help="AES key size in bits (default 256)")
    args = parser.parse_args()

    plaintext = args.text
    key = generate_key(args.key_size)

    # Encrypt, then decrypt with the same key.
    nonce, ciphertext, tag = encrypt(key, plaintext)
    decrypted = decrypt(key, nonce, ciphertext, tag)

    print(f"Algorithm           : AES-{args.key_size} (GCM mode, {ROUNDS[args.key_size]} rounds, no padding)")
    print("Plaintext           :", plaintext)
    print("Key (hex)           :", key.hex())
    print("Nonce (hex)         :", nonce.hex())
    print("Tag (hex)           :", tag.hex())
    print("Ciphertext (Base64) :", base64.b64encode(ciphertext).decode())
    print("Decrypted text      :", decrypted)
    print("Round trip OK       :", decrypted == plaintext)

    # Tamper detection: change one byte of the ciphertext and try to decrypt it.
    print()
    print("--- Tamper test: flipping one byte of the ciphertext ---")
    tampered = flip_one_byte(ciphertext)
    print("Tampered (Base64)   :", base64.b64encode(tampered).decode())
    try:
        decrypt(key, nonce, tampered, tag)
        print("Tampering detected  : False (this should not happen)")
    except ValueError as error:
        print("Decryption failed   :", error)
        print("Tampering detected  : True")


if __name__ == "__main__":
    main()
