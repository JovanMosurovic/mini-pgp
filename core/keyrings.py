import base64
import hashlib
from datetime import datetime
from typing import List, Dict

from cryptography.hazmat.primitives import serialization


from core.crypto import rsa_key_id, export_public_pem, sha1, symmetrical_encrypt, symmetrical_decrypt
from core.crypto import generate_rsa_keypair

# Helpers
def _key_id_hex(public_key) -> str:
    """
    PU_i mod 2^64 expressed as a 16-character uppercase hex string.
    Uses the least-significant 64 bits of the public modulus n.
    """
    return format(rsa_key_id(public_key), "016X")

def _now():
    """
    Returns the current date and time as a string in the format YYYY-MM-DD HH:MM.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _lock_private_key(private_key, password: str) -> str:
    hashed_pass = sha1(password.encode("utf-16"))[:16]
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    blob = symmetrical_encrypt("AES128", hashed_pass, private_key_bytes)
    return base64.b64encode(blob).decode()

def _unlock_private_key(encrypted_b64: str, password: str):
    hashed_pass = sha1(password.encode("utf-16"))[:16]
    blob = base64.b64decode(encrypted_b64)
    der = symmetrical_decrypt("AES128", hashed_pass, blob)
    return base64.b64decode(der).decode()

# Rings
class PrivateKeyRing:
    """
    Stores key pairs that belong to this user.

    Each entry (dict) in _entries contains:
        timestamp           str   "YYYY-MM-DD HH:MM"
        key_id              str   16 hex chars  — PU_i mod 2^64
        public_key_pem      str   PEM-encoded public key
        encrypted_private   str   base64(IV ‖ AES-128-CBC-ENC(H(pwd), raw_priv_PEM))
        user_id             str   "Name <email>"
        name                str
        email               str
        bits                int   1024 or 2048

    Indexed by key_id and user_id.
    """

    def __init__(self):
        self._entries: List[Dict] = []


    def add(self, name: str, email: str, bits: int, password : str):
        (private_key, public_key) = generate_rsa_keypair(bits)
        key_id = _key_id_hex(public_key)
        entry = {
            "timestamp":         _now(),
            "key_id":            key_id,
            "public_key_pem":    export_public_pem(public_key).decode(),
            "encrypted_private": _lock_private_key(private_key, password),
            "user_id":           email,
            "name":              name,
            "email":             email,
            "bits":              bits,
        }
        self._entries.append(entry)
        return key_id

    def find(self, key_id: str):
        for entry in self._entries:
            if key_id in entry:
                e = entry[key_id]
                return e
        return None

    def remove(self, key_id: str):
        if key_id not in self._entries:
            print(f"Key with id: {key_id} not found")
            return None
        del self._entries[key_id]
        return key_id


    def print_all(self):
        for entry in self._entries:
            print(entry)