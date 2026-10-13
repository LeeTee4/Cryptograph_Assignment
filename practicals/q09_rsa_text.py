"""Q9: RSA encryption and decryption of text (RSA-OAEP).

RSA is an asymmetric (public-key) cipher. Anyone can encrypt with the public key,
but only the holder of the private key can decrypt.

- Key size:   2048-bit modulus n (256 bytes), public exponent e = 65537.
- Block size: RSA is not a block cipher. One encryption handles one short message,
              and the ciphertext is always 256 bytes for a 2048-bit key.
- Padding:    OAEP with SHA-256 (PKCS#1 v2). OAEP adds randomness, so the same
              text encrypts differently every time.
- Size limit: at most k - 2*hLen - 2 bytes of plaintext, where k is the key size in
              bytes and hLen the hash size. For 2048-bit RSA with SHA-256 that is
              256 - 2*32 - 2 = 190 bytes.

Why real systems use hybrid encryption: RSA is slow and can only encrypt a few
hundred bytes at a time. So in practice (TLS, PGP and so on) the data is encrypted
with a fast symmetric cipher such as AES, and RSA is used only to encrypt that
short AES key for the receiver.
"""

import argparse
import base64
import sys
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

DEFAULT_TEXT = "I am coming tonight"
KEY_BITS = 2048
PUBLIC_KEY_FILE = Path("public.pem")
PRIVATE_KEY_FILE = Path("private.pem")


def generate_key_pair(bits=KEY_BITS):
    """Create a new RSA key pair (the private key object also contains the public key)."""
    return RSA.generate(bits)


def save_key_pair(key):
    """Save the public and private keys as PEM files."""
    PUBLIC_KEY_FILE.write_bytes(key.publickey().export_key())
    # The private key is saved unencrypted for this practical. Keep it secret.
    PRIVATE_KEY_FILE.write_bytes(key.export_key())


def load_key(path):
    """Read an RSA key back from a PEM file."""
    return RSA.import_key(path.read_bytes())


def max_plaintext_bytes(key):
    """Largest message OAEP-SHA256 can encrypt with this key: k - 2*hLen - 2."""
    return key.size_in_bytes() - 2 * SHA256.digest_size - 2


def encrypt(public_key, text):
    """Encrypt text with the public key using RSA-OAEP (SHA-256)."""
    # Step 1: set up an OAEP cipher using SHA-256 with the public key.
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    # Step 2: turn the text into bytes and encrypt. Raises ValueError if too long.
    return cipher.encrypt(text.encode("utf-8"))


def decrypt(private_key, ciphertext):
    """Decrypt RSA-OAEP ciphertext with the private key and return the text."""
    # Step 1: set up the same OAEP cipher, this time with the private key.
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    # Step 2: decrypt and turn the bytes back into text.
    return cipher.decrypt(ciphertext).decode("utf-8")


def main():
    # Read optional text from the command line. Otherwise use the sample text.
    parser = argparse.ArgumentParser(description="RSA-OAEP (SHA-256) encryption of text.")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to encrypt")
    args = parser.parse_args()
    plaintext = args.text

    # Step 1: generate a 2048-bit key pair and save it to PEM files.
    key = generate_key_pair()
    save_key_pair(key)

    # Step 2: load the keys back from the files, as a real sender and receiver would.
    public_key = load_key(PUBLIC_KEY_FILE)
    private_key = load_key(PRIVATE_KEY_FILE)

    limit = max_plaintext_bytes(public_key)
    size = len(plaintext.encode("utf-8"))

    print(f"Algorithm           : RSA-{KEY_BITS} with OAEP (SHA-256)")
    print("Public key saved to :", PUBLIC_KEY_FILE.resolve())
    print("Private key saved to:", PRIVATE_KEY_FILE.resolve(), "(not printed)")
    print("Public exponent e   :", public_key.e)
    print("Plaintext           :", plaintext)
    print(f"Plaintext size      : {size} bytes (limit {limit} bytes)")

    # Step 3: encrypt with the public key. A message over the limit is rejected.
    try:
        ciphertext = encrypt(public_key, plaintext)
    except ValueError:
        print()
        print(f"Error: the plaintext is {size} bytes, but RSA-{KEY_BITS} with OAEP-SHA256 "
              f"can encrypt at most {limit} bytes")
        print(f"       ({public_key.size_in_bytes()} - 2*{SHA256.digest_size} - 2 = {limit}). "
              "For longer data, encrypt it with AES and use RSA only for the AES key.")
        sys.exit(1)

    # Step 4: decrypt with the private key.
    decrypted = decrypt(private_key, ciphertext)

    print(f"Ciphertext ({len(ciphertext)} bytes, Base64):")
    print(base64.b64encode(ciphertext).decode())
    print("Decrypted text      :", decrypted)
    print("Round trip OK       :", decrypted == plaintext)


if __name__ == "__main__":
    main()
