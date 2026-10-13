"""Q12: MD5 message digest.

MD5 (Message Digest 5) is a cryptographic hash function. It turns input of any length
into a fixed-size "fingerprint". It is one-way: you cannot get the input back from the
digest, and there is no key.

- Digest size: 128 bits (16 bytes), shown as 32 hex characters.
- Block size:  the input is processed in 512-bit (64-byte) blocks, 64 steps per block
               (4 rounds of 16).
- Mode:        none (no key, no IV).
- Padding:     done inside the algorithm: a 1 bit, then zeros, then the 64-bit message
               length, to fill a whole number of 512-bit blocks.

Security note: MD5 is broken; practical collisions can be made in seconds. Do not use
it for security (passwords, signatures, certificates). It is still acceptable as a
non-security checksum, for example to spot accidental file corruption.
"""

import argparse
import hashlib

DEFAULT_TEXT = "I am coming tonight"
CHUNK_SIZE = 64 * 1024  # read files 64 KB at a time

# Known test vector from the MD5 specification (RFC 1321).
TEST_INPUT = "abc"
TEST_DIGEST = "900150983cd24fb0d6963f7d28e17f72"


def md5_text(text):
    """Return the MD5 digest of text, in hex."""
    # Hash functions work on bytes, so encode the text as UTF-8 first.
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def md5_file(path):
    """Return the MD5 digest of a file, in hex, reading it in chunks."""
    hasher = hashlib.md5()
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
    parser = argparse.ArgumentParser(description="MD5 message digest.")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to hash")
    parser.add_argument("--file", help="hash this file instead of the text")
    args = parser.parse_args()

    print("Security note: MD5 is broken (practical collisions). Use it only for non-security checksums.")
    print()

    # Step 1: hash the file if one was given, otherwise hash the text.
    if args.file:
        try:
            digest = md5_file(args.file)
        except OSError as error:
            parser.error(f"cannot read file: {error}")
        print("File               :", args.file)
    else:
        digest = md5_text(args.text)
        print("Text               :", args.text)
    print("MD5 digest (hex)   :", digest)
    print(f"Digest size        : {len(digest)} hex characters = {len(digest) * 4} bits")
    print()

    # Step 2: check our result against the known test vector.
    result = md5_text(TEST_INPUT)
    print(f'Test vector MD5("{TEST_INPUT}")')
    print("  Expected         :", TEST_DIGEST)
    print("  Calculated       :", result)
    print("  Match            :", result == TEST_DIGEST)
    print()

    # Step 3: avalanche effect. Changing one letter changes about half the bits.
    hash_a = md5_text("Hello")
    hash_b = md5_text("Hellp")
    changed = bits_different(hash_a, hash_b)
    print("Avalanche effect")
    print('  MD5("Hello")     :', hash_a)
    print('  MD5("Hellp")     :', hash_b)
    print(f"  Bits different   : {changed} of 128 ({changed / 128:.0%})")


if __name__ == "__main__":
    main()
