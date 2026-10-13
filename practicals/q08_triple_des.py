"""Q8: Triple DES (DES-EDE), 2-key and 3-key versions.

Triple DES is a symmetric block cipher that applies DES three times to each block
to make up for DES's short key. It uses an encrypt-decrypt-encrypt (EDE) structure:

    Encryption:  C = E_K3( D_K2( E_K1(P) ) )
    Decryption:  P = D_K1( E_K2( D_K3(C) ) )

The middle step is a DEcryption so that Triple DES stays compatible with single DES:
if K1 = K2 = K3, the first two steps cancel out and it behaves like plain DES.

- Key size:   2-key ("DES-2"): 16 bytes = K1, K2, used as K1, K2, K1.
              3-key ("DES-3"): 24 bytes = K1, K2, K3.
              Each 8-byte part has 56 real key bits and 8 parity bits.
- Block size: 8 bytes (64 bits), the same as DES.
- Mode:       CBC with a random 8-byte IV.
- Padding:    PKCS7.

Effective security:
- 3-key has 3 x 56 = 168 key bits, but a meet-in-the-middle attack (store the
  results of one half, search the other half) cuts this to about 112 bits.
- 2-key has 2 x 56 = 112 key bits, but because K1 is used twice, a known-plaintext
  attack (van Oorschot-Wiener) cuts it to about 80 bits.

Security note: Triple DES is obsolete. NIST no longer allows it for encryption
(2-key since 2015, 3-key since 2023), and its 64-bit block is open to the Sweet32
attack on long sessions. Use AES instead.

Java equivalent (javax.crypto), for comparison with the question:
    SecretKey key = new SecretKeySpec(keyBytes, "DESede");
    Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] ciphertext = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
- "DESede" is Java's name for DES-EDE, the same as DES3 here.
- "CBC" is the same as DES3.MODE_CBC.
- Java's "PKCS5Padding" is the same as PKCS7 for 8-byte blocks.
- Java's DESede expects a 24-byte key, so for 2-key you pass K1 + K2 + K1.
"""

import argparse
import base64

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

DEFAULT_TEXT = "I am coming tonight"


def generate_key(key_length):
    """Create a random Triple DES key: 16 bytes for 2-key, 24 bytes for 3-key."""
    while True:
        # Step 1: take random bytes for the key.
        candidate = get_random_bytes(key_length)

        # Step 2: set the parity bit in each byte, as DES expects.
        # adjust_key_parity raises ValueError if the key is "degenerate",
        # meaning K1 == K2 (or K2 == K3), which would reduce Triple DES to
        # single DES. That is very unlikely with random bytes, but if it
        # happens we simply generate a new key.
        try:
            return DES3.adjust_key_parity(candidate)
        except ValueError:
            continue


def encrypt(plaintext, key):
    """Encrypt text with Triple DES in CBC mode and return the IV and ciphertext joined together."""
    # Step 1: make a fresh random IV (8 bytes, one block).
    iv = get_random_bytes(DES3.block_size)

    # Step 2: set up a Triple DES cipher in CBC mode. The library works out
    # 2-key or 3-key from the key length (16 or 24 bytes).
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # Step 3: turn the text into bytes, pad to a multiple of 8 bytes and encrypt.
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))

    # Step 4: put the IV in front of the ciphertext so the receiver can decrypt.
    return iv + ciphertext


def decrypt(iv_and_ciphertext, key):
    """Split off the IV, decrypt with Triple DES in CBC mode and return the original text."""
    # Step 1: the first 8 bytes are the IV, the rest is the ciphertext.
    iv = iv_and_ciphertext[:DES3.block_size]
    ciphertext = iv_and_ciphertext[DES3.block_size:]

    # Step 2: set up the same cipher, decrypt, remove the padding and decode.
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode("utf-8")


def run_variant(title, key_length, plaintext):
    """Generate a key, encrypt and decrypt the text, and print the results."""
    key = generate_key(key_length)
    output = encrypt(plaintext, key)
    decrypted = decrypt(output, key)

    # Split the key into its 8-byte DES keys so we can show K1, K2 (and K3).
    parts = [key[i:i + 8].hex() for i in range(0, len(key), 8)]

    print(f"=== {title} ===")
    print("Plaintext                :", plaintext)
    print(f"Key ({len(key)} bytes, hex)      :", key.hex())
    for number, part in enumerate(parts, start=1):
        print(f"  K{number}                     :", part)
    if key_length == 16:
        print("  Used as                : K1, K2, K1")
    print("IV (hex)                 :", output[:DES3.block_size].hex())
    print("Ciphertext (Base64)      :", base64.b64encode(output[DES3.block_size:]).decode())
    print("IV + ciphertext (Base64) :", base64.b64encode(output).decode())
    print("Decrypted text           :", decrypted)
    print("Round trip OK            :", decrypted == plaintext)
    print()


def main():
    # Read optional text from the command line. Otherwise use the sample text.
    parser = argparse.ArgumentParser(description="2-key and 3-key Triple DES (CBC mode).")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to encrypt")
    args = parser.parse_args()

    # Part A: 2-key Triple DES (16-byte key).
    run_variant("Part A: 2-key Triple DES (DES-2), about 80-bit security", 16, args.text)

    # Part B: 3-key Triple DES (24-byte key).
    run_variant("Part B: 3-key Triple DES (DES-3), about 112-bit security", 24, args.text)


if __name__ == "__main__":
    main()
