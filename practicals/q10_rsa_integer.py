"""Q10: RSA encryption and decryption of an integer (textbook RSA).

RSA is an asymmetric (public-key) cipher built on modular arithmetic:

    Key generation:  n = p * q,  phi = (p - 1) * (q - 1)
                     choose e with gcd(e, phi) = 1,  d = e^-1 mod phi
    Encryption:      c = m^e mod n      (public key: e, n)
    Decryption:      m = c^d mod n      (private key: d, n)

- Key size:   Part A uses tiny primes so every value can be worked by hand.
              Part B uses a realistic 2048-bit modulus n.
- Block size: the message must be an integer with 0 <= m < n.
- Mode:       none.
- Padding:    none ("textbook RSA").

Security note: unpadded RSA is deterministic (the same m always gives the same c)
and insecure, so it is only for teaching. Real systems use OAEP padding (see Q9).
"""

import argparse
import math
import sys

from Crypto.PublicKey import RSA

DEFAULT_TEXT = "I am coming tonight"


def is_prime(number):
    """Check whether a small number is prime by trial division."""
    if number < 2:
        return False
    for divisor in range(2, math.isqrt(number) + 1):
        if number % divisor == 0:
            return False
    return True


def make_key(p, q, e):
    """Build an RSA key from primes p and q and public exponent e. Returns (n, phi, d)."""
    if not is_prime(p) or not is_prime(q):
        raise ValueError(f"p and q must both be prime (got p = {p}, q = {q}).")
    if p == q:
        raise ValueError("p and q must be different primes.")

    # Step 1: the modulus n is the product of the two primes.
    n = p * q
    # Step 2: Euler's totient phi(n) counts the numbers below n that share no factor with n.
    phi = (p - 1) * (q - 1)

    # Step 3: e must be between 1 and phi and share no factor with phi,
    # otherwise it has no inverse and we cannot find d.
    if not 1 < e < phi or math.gcd(e, phi) != 1:
        raise ValueError(f"e must satisfy 1 < e < phi and gcd(e, phi) = 1 "
                         f"(got e = {e}, phi = {phi}, gcd = {math.gcd(e, phi)}).")

    # Step 4: d is the modular inverse of e, meaning (e * d) mod phi = 1.
    d = pow(e, -1, phi)
    return n, phi, d


def check_range(value, n, name="message m"):
    """RSA works modulo n, so the value must satisfy 0 <= value < n."""
    if not 0 <= value < n:
        raise ValueError(f"The {name} must satisfy 0 <= value < n, but it is {value} "
                         f"and n = {n}. A larger value would wrap around modulo n.")


def encrypt(m, e, n):
    """Textbook RSA encryption: c = m^e mod n."""
    check_range(m, n, "message m")
    return pow(m, e, n)


def decrypt(c, d, n):
    """Textbook RSA decryption: m = c^d mod n."""
    check_range(c, n, "ciphertext c")
    return pow(c, d, n)


def short(number):
    """Show a very large number as the first and last few hex digits."""
    digits = format(number, "x")
    if len(digits) <= 40:
        return digits
    return f"{digits[:16]}...{digits[-16:]} ({number.bit_length()} bits)"


def part_a(p, q, e, m):
    """Worked example with small primes, printing every intermediate value."""
    print("=== Part A: small worked example ===")
    n, phi, d = make_key(p, q, e)
    print(f"p                    = {p}")
    print(f"q                    = {q}")
    print(f"n = p * q            = {p} * {q} = {n}")
    print(f"phi = (p-1)*(q-1)    = {p - 1} * {q - 1} = {phi}")
    print(f"e                    = {e}   (gcd(e, phi) = {math.gcd(e, phi)})")
    print(f"d = e^-1 mod phi     = {d}   (check: e * d mod phi = {e * d % phi})")
    print(f"Public key  (e, n)   = ({e}, {n})")
    print(f"Private key (d, n)   = ({d}, {n})")
    print(f"Message m            = {m}")

    c = encrypt(m, e, n)
    print(f"c = m^e mod n        = {m}^{e} mod {n} = {c}")

    decrypted = decrypt(c, d, n)
    print(f"m = c^d mod n        = {c}^{d} mod {n} = {decrypted}")
    print("Round trip OK        :", decrypted == m)

    # Textbook RSA is deterministic: encrypting the same m again gives the same c.
    print("Same c again         :", encrypt(m, e, n) == c, "(deterministic, so insecure)")

    # Show the range check: m = n is not allowed.
    try:
        encrypt(n, e, n)
    except ValueError as error:
        print(f"Validation (m = n)   : rejected. {error}")
    print()


def part_b(text):
    """Realistic 2048-bit RSA on an integer made from the sample text."""
    print("=== Part B: realistic 2048-bit key ===")

    # Step 1: generate a 2048-bit key with pycryptodome. key.n, key.e and key.d
    # are ordinary Python integers.
    key = RSA.generate(2048)
    print("n (hex)              =", short(key.n))
    print("e                    =", key.e)
    print(f"d                    = (private, {key.d.bit_length()} bits, not printed)")

    # Step 2: turn the text into one big integer m (its bytes read as a number).
    m = int.from_bytes(text.encode("utf-8"), "big")
    print("Text                 :", text)
    print("m (text as integer)  =", m)

    # Step 3: encrypt and decrypt with pow(), exactly as in Part A.
    c = encrypt(m, key.e, key.n)
    print("c = m^e mod n (hex)  =", short(c))
    decrypted = decrypt(c, key.d, key.n)
    print("m = c^d mod n        =", decrypted)

    # Step 4: turn the integer back into text.
    decrypted_text = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, "big").decode("utf-8")
    print("Decrypted text       :", decrypted_text)
    print("Round trip OK        :", decrypted == m and decrypted_text == text)
    print()


def part_c_test_case(n=35, e=5, c=10, expected=5):
    """Test case: recover m from n = 35, e = 5, c = 10 (expected m = 5)."""
    print("=== Test case: n = 35, e = 5, c = 10 ===")

    # Step 1: n is tiny, so factor it by trial division to find p and q.
    p = next(i for i in range(2, n) if n % i == 0)
    q = n // p
    print(f"Factor n             : {n} = {p} * {q}")

    # Step 2: compute phi and the private exponent d.
    _, phi, d = make_key(p, q, e)
    print(f"phi = (p-1)*(q-1)    = {p - 1} * {q - 1} = {phi}")
    print(f"d = e^-1 mod phi     = {d}   (check: e * d mod phi = {e * d % phi})")

    # Step 3: decrypt the ciphertext.
    m = decrypt(c, d, n)
    print(f"m = c^d mod n        = {c}^{d} mod {n} = {m}")
    print(f"Expected m = {expected}       :", m == expected)
    print(f"Re-encrypt m^e mod n = {m}^{e} mod {n} = {encrypt(m, e, n)}")
    print()


def main():
    # Read optional values from the command line. Otherwise use the defaults.
    parser = argparse.ArgumentParser(description="Textbook RSA on integers.")
    parser.add_argument("--p", type=int, default=61, help="first prime for Part A (default 61)")
    parser.add_argument("--q", type=int, default=53, help="second prime for Part A (default 53)")
    parser.add_argument("--e", type=int, default=17, help="public exponent for Part A (default 17)")
    parser.add_argument("--message", type=int, default=65, help="integer to encrypt in Part A (default 65)")
    parser.add_argument("--text", default=DEFAULT_TEXT, help="text to turn into an integer for Part B")
    args = parser.parse_args()

    print("Security note: textbook RSA has no padding and is insecure. For teaching only.")
    print()

    try:
        part_a(args.p, args.q, args.e, args.message)
        part_c_test_case()
        part_b(args.text)
    except ValueError as error:
        print("Error:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
