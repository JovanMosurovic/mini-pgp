import base64
import json
from datetime import datetime

from cryptography.hazmat.primitives import serialization

from core.crypto import rsa_key_id, export_public_pem, sha1, symmetrical_encrypt, symmetrical_decrypt, load_public_pem, \
    load_private_pem, export_private_pem
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
    return serialization.load_der_private_key(der, password=None)

# Rings
class PrivateKeyRing:
    """
    Stores key pairs that belong to this user.

    Each entry (dict) in _entries contains:
        timestamp           str   "YYYY-MM-DD HH:MM"
        key_id              str   16 hex chars  — PU_i mod 2^64
        public_key_pem      str   PEM-encoded public key
        encrypted_private   str   base64(IV ‖ AES-128-CBC-ENC(H(pwd), raw_priv_PEM))
        user_id             str   email
        name                str
        email               str
        bits                int   1024 or 2048

    Indexed by key_id and user_id.
    """

    def __init__(self):
        self._entries= {}


    def add_keypair(self, name, email, private_key, public_key, password):
        key_id = _key_id_hex(public_key)
        self._entries[key_id] = {
            "timestamp":         _now(),
            "key_id":            key_id,
            "public_key_pem":    export_public_pem(public_key).decode(),
            "encrypted_private": _lock_private_key(private_key, password),
            "user_id":           email,
            "name":              name,
            "email":             email,
            "bits":              public_key.key_size,
        }
        return key_id

    def add(self, name, email, bits, password):
        private_key, public_key = generate_rsa_keypair(bits)
        return self.add_keypair(name, email, private_key, public_key, password)

    def import_pem(self, path, file_password, name, email, ring_password):
        with open(path, "rb") as f:
            private_key = load_private_pem(f.read(), file_password)
        return self.add_keypair(name, email, private_key, private_key.public_key(), ring_password)

    def export_pem(self, key_id, path, ring_password, out_password):
        private_key = self.get_private_key(key_id, ring_password)
        with open(path, "wb") as f:
            f.write(export_private_pem(private_key, out_password))

    def find(self, key_id: str):
        return self._entries.get(key_id)

    def get_private_key(self, key_id, password):
        """Get and decrypt private key.

        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        """
        entry = self._entries.get(key_id)

        if entry is None:
            raise KeyError(f"Key with id: {key_id} not found")

        try:
            return _unlock_private_key(entry["encrypted_private"], password)
        except Exception:
            raise ValueError("Invalid password for this private key.")

    def remove(self, key_id: str):
        return self._entries.pop(key_id, None) is not None

    def to_rows(self):
        return [(e["timestamp"], e["key_id"], e["name"], e["email"], e["bits"])
                for e in self._entries.values()]

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self._entries, f, indent=2)

    def load(self, path):
        with open(path) as f:
            self._entries = json.load(f)

    def print_all(self):
        for entry in self._entries.values():
            print(entry)

class PublicKeyRing:
    def __init__(self):
        self._entries = {}

    def add(self, name, email, public_key, owner_trust=None, signature_trusts=None):
        if owner_trust is not None and not (1 <= owner_trust <= 10):
            raise ValueError("owner_trust must be an integer between 1 and 10 (or None).")

        key_id = _key_id_hex(public_key)
        self._entries[key_id] = {
            "timestamp":      _now(),
            "key_id":         key_id,
            "public_key_pem": export_public_pem(public_key).decode(),
            "user_id":        email,
            "name":           name,
            "email":          email,
            "bits":           public_key.key_size,
            "owner_trust":      owner_trust,             # 1-10 or None (optional)
            "signature_trusts": signature_trusts or [],  # list (optional)
        }
        return key_id

    def find(self, key_id):
        return self._entries.get(key_id)

    def remove(self, key_id):
        return self._entries.pop(key_id, None) is not None

    def to_rows(self):
        return [(e["timestamp"], e["key_id"], e["name"], e["email"], e["bits"])
                for e in self._entries.values()]

    def import_pem(self, path, name, email, owner_trust=None, signature_trusts=None):
        """Import a public key from .pem -> keyring"""
        with open(path, "rb") as f:
            pub = load_public_pem(f.read())
        return self.add(name, email, pub, owner_trust, signature_trusts)

    def export_pem(self, key_id, path):
        """Export a public key from keyring -> .pem"""
        entry = self._entries.get(key_id)

        if entry is None:
            raise KeyError(f"Key {key_id} not found")

        with open(path, "w") as f:
            f.write(entry["public_key_pem"])

    def get_public_key(self, key_id):
        """Get a public key (object) by key_id - for encryption/verification"""
        entry = self._entries.get(key_id)
        return load_public_pem(entry["public_key_pem"].encode()) if entry else None

