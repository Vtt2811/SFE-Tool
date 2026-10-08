# SecureVault — Secure File Encryption Tool

A command-line Python tool for encrypting and decrypting files, and for
storing a master password safely (hashed, never in plaintext).

## Why this project is more than a toy script

- **Real cryptography, used correctly**: encryption keys are never derived
  directly from a password. Instead, PBKDF2-HMAC-SHA256 with a random
  16-byte salt and 390,000 iterations (OWASP's current recommended minimum)
  stretches the password into a key, so the same password produces a
  different key every time, and brute-forcing is computationally expensive.
- **Authenticated encryption**: uses Fernet (AES-128-CBC + HMAC) from the
  `cryptography` library, so a tampered or corrupted ciphertext is detected
  and rejected rather than silently decrypted into garbage.
- **Passwords are never stored in plaintext.** The password "vault" feature
  stores only a salt and a PBKDF2 hash — exactly the pattern real
  authentication systems use (the same idea behind bcrypt/Argon2-based
  login systems, just built from first principles with PBKDF2).
- **Fails closed, not open**: a wrong password or corrupted file raises a
  clear error and writes nothing, instead of producing silently wrong
  output.
- **Clean CLI design**: subcommands (`encrypt`, `decrypt`, `set-password`,
  `check-password`) built with `argparse`, password input via `getpass`
  (never echoed or left in shell history).

## Usage

```bash
pip install cryptography

# Encrypt a file (prompts for a password, confirms it)
python vault.py encrypt secret.txt
# -> creates secret.txt.enc

# Decrypt it back
python vault.py decrypt secret.txt.enc -o secret_decrypted.txt

# Store a master password (only a salted hash is saved to disk)
python vault.py set-password

# Verify a password against the stored hash
python vault.py check-password
```

## How it works, in short

1. **Encrypting a file**: a random salt is generated, combined with your
   password through PBKDF2 to derive a 32-byte key, and that key encrypts
   the file with Fernet. The salt (not secret) is prepended to the
   ciphertext so decryption can regenerate the same key later.
2. **Decrypting**: the salt is read back out, the same key is re-derived
   from the password you provide, and Fernet either successfully decrypts
   or raises `InvalidToken` — which the tool catches and reports as a
   clear "wrong password or corrupted file" error.
3. **Password vault**: `set-password` never writes your password to disk.
   It writes `salt + PBKDF2(password, salt)`. `check-password` re-runs the
   same derivation on the input and compares digests — if someone steals
   the metadata file, they get a hash, not a password.

## What I'd extend next

- Swap the hand-rolled PBKDF2 password check for Argon2id (stronger against
  GPU-based cracking).
- Add a `--recursive` flag to encrypt/decrypt entire directories.
- Add a progress bar for large files (currently loads whole file into memory).
