# Information Security Practicals (Questions 6–12)

Python implementations of DES, AES, Triple DES, RSA (text and integer), SHA-1 and MD5,
using the [pycryptodome](https://pycryptodome.readthedocs.io/) library.

## Requirements

- Python 3.10 or newer
- pycryptodome (installed from `requirements.txt`)

> Do **not** install `pycrypto`. It is abandoned and clashes with pycryptodome, which
> uses the same `Crypto` package name.

## Setup

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -c "import Crypto; print(Crypto.__version__)"
```

If PowerShell blocks the activation script, run this once and then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

(In Command Prompt, activate with `.venv\Scripts\activate.bat` instead.)

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c "import Crypto; print(Crypto.__version__)"
```

The last command should print a version number such as `3.24.1`.

## Running the scripts

Activate the virtual environment first, then run the scripts from the project folder.
Every script uses the sample text `"I am coming tonight"` unless you pass `--text`.

| Question | Algorithm   | Command                                |
|----------|-------------|----------------------------------------|
| Q6       | DES         | `python practicals/q06_des.py`         |
| Q7       | AES         | `python practicals/q07_aes.py`         |
| Q8       | Triple DES  | `python practicals/q08_triple_des.py`  |
| Q9       | RSA (text)  | `python practicals/q09_rsa_text.py`    |
| Q10      | RSA (integer)| `python practicals/q10_rsa_integer.py`|
| Q11      | SHA-1       | `python practicals/q11_sha1.py`        |
| Q12      | MD5         | `python practicals/q12_md5.py`         |

To use your own text:

```
python practicals/q07_aes.py --text "Meet me at the library"
```

Run any script with `--help` to see its options.

Each cipher script prints the generated key (and IV, where the mode uses one), the
ciphertext in hex or Base64, the decrypted text, and whether it matches the original.
The hash scripts print the message digest.

## Project layout

```
.
├── .venv/              virtual environment (not submitted)
├── practicals/         one script per question (q06 to q12)
├── requirements.txt    pycryptodome
├── README.md           this file
└── CLAUDE.md           coding conventions for the practicals
```
