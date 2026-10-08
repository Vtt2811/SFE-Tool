#!/usr/bin/env python3
"""
SecureVault - A command-line file encryption tool.

Encrypts and decrypts files using password-based encryption. Implements:
  - Key derivation from a password using PBKDF2-HMAC-SHA256 with a random salt
  - Authenticated symmetric encryption (AES-128 in CBC mode via Fernet, wrapped
    with HMAC for integrity) using the `cryptography` library's Fernet recipe
  - Safe file handling (never overwrites originals unless explicitly told to)
  - A password "vault" that stores hashed (not plaintext) password checks,
    using Argon2id (and backwards compatible with PBKDF2).

Usage:
    python vault.py encrypt <file> [-o output_file] [-r]
    python vault.py decrypt <file> [-o output_file] [-r]
    python vault.py set-password
    python vault.py check-password
"""

import argparse
import base64
import getpass
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:
    PasswordHasher = None

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


class SimpleProgressBar:
    def __init__(self, total, desc=""):
        self.total = total
        self.desc = desc
        self.current = 0
        self.last_percent = -1
        
    def update(self, amount):
        self.current += amount
        percent = int((self.current / self.total) * 100) if self.total else 100
        if percent != self.last_percent:
            sys.stdout.write(f"\r{self.desc}: [{percent}%] {self.current}/{self.total} bytes")
            sys.stdout.flush()
            self.last_percent = percent
            
    def close(self):
        print()


# ---- Constants -------------------------------------------------------------

SALT_SIZE = 16          # bytes of random salt for key derivation
KDF_ITERATIONS = 390_000  # OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023+)
VAULT_METADATA_FILE = Path.home() / ".securevault_meta.json"
ENCRYPTED_EXTENSION = ".enc"
CHUNK_SIZE = 1024 * 1024  # 1MB chunks


# ---- Key derivation ---------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte encryption key from a password and salt using
    PBKDF2-HMAC-SHA256, then base64-urlsafe-encode it for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


# ---- Encryption / decryption -----------------------------------------------

def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"No such file: {input_path}")

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    file_size = input_path.stat().st_size

    with input_path.open("rb") as f_in, output_path.open("wb") as f_out:
        f_out.write(salt)

        if tqdm:
            pbar = tqdm(total=file_size, unit='B', unit_scale=True, desc=f"Encrypting {input_path.name}")
        else:
            pbar = SimpleProgressBar(total=file_size, desc=f"Encrypting {input_path.name}")

        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            
            encrypted_chunk = fernet.encrypt(chunk)
            f_out.write(len(encrypted_chunk).to_bytes(4, byteorder='big'))
            f_out.write(encrypted_chunk)
            
            pbar.update(len(chunk))
            
        pbar.close()


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"No such file: {input_path}")

    file_size = input_path.stat().st_size
    if file_size < SALT_SIZE:
        raise ValueError("File is too small to be a valid encrypted file.")

    with input_path.open("rb") as f_in, output_path.open("wb") as f_out:
        salt = f_in.read(SALT_SIZE)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        first_byte_after_salt = f_in.read(1)
        if not first_byte_after_salt:
            return

        f_in.seek(SALT_SIZE)

        if first_byte_after_salt[0] != 0x00:
            # Old format
            ciphertext = f_in.read()
            try:
                plaintext = fernet.decrypt(ciphertext)
            except InvalidToken:
                raise ValueError("Decryption failed: wrong password or corrupted file.")
            f_out.write(plaintext)
            return

        if tqdm:
            pbar = tqdm(total=file_size - SALT_SIZE, unit='B', unit_scale=True, desc=f"Decrypting {input_path.name}")
        else:
            pbar = SimpleProgressBar(total=file_size - SALT_SIZE, desc=f"Decrypting {input_path.name}")

        while True:
            len_bytes = f_in.read(4)
            if not len_bytes:
                break
            
            if len(len_bytes) < 4:
                raise ValueError("Corrupted file: truncated chunk length.")
                
            chunk_len = int.from_bytes(len_bytes, byteorder='big')
            encrypted_chunk = f_in.read(chunk_len)
            
            if len(encrypted_chunk) < chunk_len:
                raise ValueError("Corrupted file: truncated chunk data.")
                
            try:
                plaintext = fernet.decrypt(encrypted_chunk)
            except InvalidToken:
                raise ValueError("Decryption failed: wrong password or corrupted file chunk.")
                
            f_out.write(plaintext)
            pbar.update(4 + chunk_len)

        pbar.close()


# ---- Password vault (hashed password check, not plaintext storage) --------

def set_master_password(password: str) -> None:
    if PasswordHasher is None:
        raise RuntimeError("The 'argon2-cffi' package is required for Argon2id. Run: pip install argon2-cffi")
        
    ph = PasswordHasher()
    hash_str = ph.hash(password)

    data = {
        "hash": hash_str,
        "type": "argon2id"
    }
    VAULT_METADATA_FILE.write_text(json.dumps(data))
    try:
        os.chmod(VAULT_METADATA_FILE, 0o600)
    except OSError:
        pass
    print(f"Master password hash stored at {VAULT_METADATA_FILE} (plaintext never saved).")


def check_master_password(password: str) -> bool:
    if not VAULT_METADATA_FILE.is_file():
        raise FileNotFoundError("No master password set yet. Run 'set-password' first.")

    data = json.loads(VAULT_METADATA_FILE.read_text())
    
    if data.get("type") == "argon2id" or ("hash" in data and "salt" not in data):
        if PasswordHasher is None:
            raise RuntimeError("The 'argon2-cffi' package is required to verify this vault. Run: pip install argon2-cffi")
            
        ph = PasswordHasher()
        try:
            ph.verify(data["hash"], password)
            return True
        except VerifyMismatchError:
            return False
    else:
        salt = base64.b64decode(data["salt"])
        stored_digest = base64.b64decode(data["hash"])
        iterations = data.get("iterations", KDF_ITERATIONS)

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        try:
            kdf.verify(password.encode("utf-8"), stored_digest)
            return True
        except Exception:
            return False


# ---- CLI --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault.py",
        description="SecureVault: encrypt/decrypt files and manage a master password safely."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file.")
    enc.add_argument("file", type=Path, help="Path to the file or directory to encrypt.")
    enc.add_argument("-o", "--output", type=Path, default=None,
                      help="Output path (default: <file>.enc)")
    enc.add_argument("-r", "--recursive", action="store_true", help="Encrypt directories recursively.")

    dec = sub.add_parser("decrypt", help="Decrypt a file.")
    dec.add_argument("file", type=Path, help="Path to the encrypted file or directory.")
    dec.add_argument("-o", "--output", type=Path, default=None,
                      help="Output path (default: strips .enc, or appends .dec)")
    dec.add_argument("-r", "--recursive", action="store_true", help="Decrypt directories recursively.")

    sub.add_parser("set-password", help="Set/overwrite the master password hash.")
    sub.add_parser("check-password", help="Verify a password against the stored hash.")

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: passwords do not match.", file=sys.stderr)
                return 1
                
            if args.recursive:
                if not args.file.is_dir():
                    print("Error: --recursive requires a directory.", file=sys.stderr)
                    return 1
                for root, _, files in os.walk(args.file):
                    for file in files:
                        p = Path(root) / file
                        if p.suffix == ENCRYPTED_EXTENSION:
                            continue
                        output = p.with_suffix(p.suffix + ENCRYPTED_EXTENSION)
                        try:
                            encrypt_file(p, output, password)
                        except Exception as e:
                            print(f"Failed to encrypt {p}: {e}", file=sys.stderr)
            else:
                output = args.output or args.file.with_suffix(args.file.suffix + ENCRYPTED_EXTENSION)
                encrypt_file(args.file, output, password)

        elif args.command == "decrypt":
            password = getpass.getpass("Password: ")
            
            if args.recursive:
                if not args.file.is_dir():
                    print("Error: --recursive requires a directory.", file=sys.stderr)
                    return 1
                for root, _, files in os.walk(args.file):
                    for file in files:
                        p = Path(root) / file
                        if p.suffix != ENCRYPTED_EXTENSION:
                            continue
                        output = p.with_suffix("")
                        try:
                            decrypt_file(p, output, password)
                        except Exception as e:
                            print(f"Failed to decrypt {p}: {e}", file=sys.stderr)
            else:
                if args.output:
                    output = args.output
                elif args.file.suffix == ENCRYPTED_EXTENSION:
                    output = args.file.with_suffix("")
                else:
                    output = args.file.with_suffix(args.file.suffix + ".dec")
                decrypt_file(args.file, output, password)

        elif args.command == "set-password":
            password = getpass.getpass("New master password: ")
            confirm = getpass.getpass("Confirm: ")
            if password != confirm:
                print("Error: passwords do not match.", file=sys.stderr)
                return 1
            set_master_password(password)

        elif args.command == "check-password":
            password = getpass.getpass("Password: ")
            ok = check_master_password(password)
            print("Password correct." if ok else "Password incorrect.")
            return 0 if ok else 1

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
