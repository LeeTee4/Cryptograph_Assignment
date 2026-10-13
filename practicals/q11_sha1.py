"""Q11: SHA-1 message digest.

SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function. It turns input of
any length into a fixed-size "fingerprint". It is one-way: you cannot get the input
back from the digest, and there is no key.

- Digest size: 160 bits (20 bytes), shown as 40 hex characters.
- Block size:  the input is processed in 512-bit (64-byte) blocks, 80 steps per block.
- Mode:        none (no key, no IV).
- Padding:     done inside the algorithm: a 1 bit, then zeros, then the 64-bit message
               length, to fill a whole number of 512-bit blocks.

Security note: SHA-1 is broken for collision resistance (the SHAttered attack, 2017,
produced two different PDFs with the same SHA-1). Do not use it for security; use SHA-256.
"""

import argparse
import hashlib

DEFAULT_TEXT = "I am coming tonight"
CHUNK_SIZE = 64 * 1024  # read files 64 KB at a time

# Known test vector from the SHA-1 standard (FIPS 180).
TEST_INPUT = "abc"
TEST_DIGEST = "a9993e364706816aba3e25717850c26c9cd0d89d"


def sha1_text(text):
    """Return the SHA-1 digest of text, in hex."""
    # Hash functions work on bytes, so encode the text as UTF-8 first.
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def sha1_file(path):
    """Return the SHA-1 digest of a file, in hex, reading it in chunks."""
    hasher = hashlib.sha1()
    with open(path, "rb") as file:
        # Feed the file in pieces so even a very large file uses little memory.
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def bits_different(hex_a, hex_b):
    """Count how many bits differ between two digests (XOR them, count the 1s)."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def main():
    # Read optional text or a file name from the command line.
    parser = argparse.ArgumentParser(description="SHA-1 message digest.")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to hash")
    parser.add_argument("--file", help="hash this file instead of the text")
    args = parser.parse_args()

    print("Security note: SHA-1 is broken for collisions (SHAttered, 2017). Do not use it for security.")
    print()

    # Step 1: hash the file if one was given, otherwise hash the text.
    if args.file:
        try:
            digest = sha1_file(args.file)
        except OSError as error:
            parser.error(f"cannot read file: {error}")
        print("File               :", args.file)
    else:
        digest = sha1_text(args.text)
        print("Text               :", args.text)
    print("SHA-1 digest (hex) :", digest)
    print(f"Digest size        : {len(digest)} hex characters = {len(digest) * 4} bits")
    print()

    # Step 2: check our result against the known test vector.
    result = sha1_text(TEST_INPUT)
    print(f'Test vector SHA-1("{TEST_INPUT}")')
    print("  Expected         :", TEST_DIGEST)
    print("  Calculated       :", result)
    print("  Match            :", result == TEST_DIGEST)
    print()

    # Step 3: avalanche effect. Changing one letter changes about half the bits.
    hash_a = sha1_text("Hello")
    hash_b = sha1_text("Hellp")
    changed = bits_different(hash_a, hash_b)
    print("Avalanche effect")
    print('  SHA-1("Hello")   :', hash_a)
    print('  SHA-1("Hellp")   :', hash_b)
    print(f"  Bits different   : {changed} of 160 ({changed / 160:.0%})")


if __name__ == "__main__":
    main()
