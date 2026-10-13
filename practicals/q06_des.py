"""Q6: DES encryption and decryption.

DES (Data Encryption Standard) is a symmetric block cipher: the same secret key
is used to encrypt and to decrypt.

- Key size:   8 bytes (64 bits), of which only 56 bits are used. The other 8 are parity bits.
- Block size: 8 bytes (64 bits).
- Mode:       CBC (Cipher Block Chaining) with a random 8-byte IV.
- Padding:    PKCS7, so the plaintext fills a whole number of 8-byte blocks.

Security note: DES is obsolete. Its 56-bit effective key can be brute-forced in
hours with dedicated hardware, so it must not be used for real data.

Why not ECB mode: ECB encrypts every block on its own, so identical plaintext
blocks give identical ciphertext blocks and patterns in the data show through.
CBC mixes each block with the previous one (and the first with the IV), which hides
those patterns.
"""

import argparse
import base64

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_TEXT = "I am coming tonight"


def generate_key():
    """Create a random 8-byte DES key."""
    return get_random_bytes(8)


def encrypt(plaintext, key):
    """Encrypt text with DES-CBC and return the IV and ciphertext joined together."""
    # Step 1: make a fresh random IV (8 bytes, the size of one DES block).
    iv = get_random_bytes(DES.block_size)

    # Step 2: set up a DES cipher in CBC mode with our key and IV.
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Step 3: turn the text into bytes and pad it to a multiple of 8 bytes.
    padded = pad(plaintext.encode("utf-8"), DES.block_size)

    # Step 4: encrypt the padded bytes.
    ciphertext = cipher.encrypt(padded)

    # Step 5: put the IV in front of the ciphertext. The IV is not secret,
    # and the receiver needs it to decrypt.
    return iv + ciphertext


def decrypt(iv_and_ciphertext, key):
    """Split off the IV, decrypt with DES-CBC and return the original text."""
    # Step 1: the first 8 bytes are the IV, the rest is the ciphertext.
    iv = iv_and_ciphertext[:DES.block_size]
    ciphertext = iv_and_ciphertext[DES.block_size:]

    # Step 2: set up the same DES-CBC cipher with the same key and IV.
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Step 3: decrypt, remove the padding and turn the bytes back into text.
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, DES.block_size).decode("utf-8")


def main():
    # Read optional text from the command line. Otherwise use the sample text.
    parser = argparse.ArgumentParser(description="DES encryption and decryption (CBC mode).")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to encrypt")
    args = parser.parse_args()

    plaintext = args.text
    key = generate_key()

    # Encrypt, then decrypt using only the key and the combined IV + ciphertext.
    output = encrypt(plaintext, key)
    decrypted = decrypt(output, key)

    iv = output[:DES.block_size]
    ciphertext = output[DES.block_size:]

    print("Algorithm                : DES (CBC mode, PKCS7 padding)")
    print("Plaintext                :", plaintext)
    print("Key (hex)                :", key.hex())
    print("IV (hex)                 :", iv.hex())
    print("Ciphertext (Base64)      :", base64.b64encode(ciphertext).decode())
    print("IV + ciphertext (Base64) :", base64.b64encode(output).decode())
    print("Decrypted text           :", decrypted)
    print("Round trip OK            :", decrypted == plaintext)


if __name__ == "__main__":
    main()
