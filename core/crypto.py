"""
Wrapper around `cryptography` library.

Dependency: `pip install cryptography`
"""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES, CAST5
except ImportError:  # for older versions
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# RSA
def generate_rsa_keypair(bits):
    """Generate RSA keypair of a given size.

    :param bits: Size of the keypair in bits (can be 1024 or 2048)
    :type bits: int

    :return: Tuple of private and public keys
    :rtype: tuple
    """
    if bits not in (1024, 2048):
        raise ValueError("Invalid key size. Supported sizes are 1024 and 2048 bits.")
    rsa_e = 65537 # best value for e in rsa
    private_key = rsa.generate_private_key(public_exponent=rsa_e, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_sign(private_key, data):
    """
    Signs the given data using the provided private key using the RSA algorithm.

    :param private_key: Private key used for signing
    :type private_key: rsa.RSAPrivateKey
    :param data: Data to be signed
    :type data: bytes

    :return: Signature of the data
    :rtype: bytes
    """
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())

def rsa_verify(public_key, data, signature):
    """
    Verifies the authenticity of a digital signature using the RSA algorithm.

    :param public_key: The RSA public key used for verifying the signature.
    :type public_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    :param data: The original data whose signature is being verified.
    :type data: bytes
    :param signature: The digital signature to verify.
    :type signature: bytes

    :return: True if the signature is valid, False otherwise.
    :rtype: bool
    """
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except InvalidSignature:
        return False

def rsa_encrypt(public_key, data):
    """
    Encrypts data using the provided public key and PKCS1v15 padding.

    :param public_key: The public key used for encryption.
    :type public_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    :param data: The data to be encrypted.
    :type data: bytes

    :return: The encrypted data.
    :rtype: bytes
    """
    return public_key.encrypt(data, padding.PKCS1v15())

def rsa_decrypt(private_key, data):
    """
    Decrypts the given data using the provided RSA private key and PKCS1v15 padding.

    :param private_key: The RSA private key object used for decryption.
    :type private_key: rsa.RSAPrivateKey
    :param data: The encrypted data to be decrypted.
    :type data: bytes

    :return: The decrypted plaintext data.
    :rtype: bytes
    """
    return private_key.decrypt(data, padding.PKCS1v15())

def rsa_key_id(public_key):
    """
    Returns the key ID of the given RSA public key.

    :param public_key: The RSA public key.
    :type public_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey

    :return: The key ID.
    :rtype: int
    """
    n = public_key.public_numbers().n
    return n & ((1 << 64) - 1)

# PEM
def export_public_pem(public_key):
    """
    Returns the public key in PEM format.

    For saving in JSON format, use `decode()`.

    :param public_key: The RSA public key.
    :type public_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey

    :return: The public key in PEM format.
    :rtype: bytes
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def export_private_pem(private_key, password):
    """
    Returns the private key in PEM format.

    The library chooses the best available encryption algorithm for the given password.

    :param private_key: The RSA private key.
    :type private_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    :param password: The password to encrypt the private key.
    :type password: str

    :return: The private key in PEM format.
    :rtype: bytes
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

def load_public_pem(pem):
    """
    Loads a public key from PEM format.

    :param pem: The public key in PEM format.
    :type pem: bytes

    :return: The loaded public key.
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    """
    return serialization.load_pem_public_key(pem)

def load_private_pem(pem, password):
    """
    Loads a private key from PEM format.

    :param pem: The private key in PEM format.
    :type pem: bytes
    :param password: The password to decrypt the private key.
    :type password: str

    :return: The loaded private key.
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """
    return serialization.load_pem_private_key(pem, password=password.encode())

# HASH
def sha1(data):
    """
    Returns the SHA-1 hash of the given input data.

    :param data: Input data to hash
    :type data: bytes

    :return: The SHA-1 hashed output
    :rtype: bytes
    """
    h = hashes.Hash(hashes.SHA1())
    h.update(data)
    return h.finalize()

# Symmetrical ciphers - AES128 and 3DES (CBC + PKCS7 padding + random IV)

# Name -> (algorithm_class, key_length [bytes], block_length [bytes])
_ALGOS = {
    "AES128": (algorithms.AES, 16, 16),  # 128-bit key, 128-bit block
    "3DES": (algorithms.TripleDES, 24, 8),           # 192-bit key, 64-bit block
}

def new_session_key(algorithm):
    """
    Generates a new session key for the given algorithm.

    :param algorithm: The algorithm to use for generating the session key.
    :type algorithm: str

    :return: The generated session key.
    :rtype: bytes
    """
    _, key_len, _ = _ALGOS[algorithm]
    return os.urandom(key_len)

def symmetrical_encrypt(algo, key, data):
    """
    Encrypts data using a symmetric block cipher in CBC mode.

    A random IV is generated for each encryption and prepended to the
    ciphertext, so the decrypt function can extract it from the returned bytes
    instead of receiving it as a separate argument.

    :param algo: Name of the symmetric algorithm, e.g. "AES128" or "3DES".
    :param key: Symmetric key bytes for the selected algorithm.

    :param data: Plaintext bytes to encrypt.
    :return: Bytes containing IV followed by ciphertext.
    """
    algo_cls, _, block_len = _ALGOS[algo]
    iv = os.urandom(block_len)
    padder = sym_padding.PKCS7(block_len * 8).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algo_cls(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def symmetrical_decrypt(algo, key, data):
    """
    Decrypts data produced by sym_encrypt.

    The IV is read from the beginning of the input bytes. The remaining bytes
    are decrypted using the selected symmetric algorithm in CBC mode, then
    PKCS7 padding is removed.

    :param algo: Name of the symmetric algorithm, e.g. "AES128" or "3DES".
    :param key: Symmetric key bytes for the selected algorithm.

    :param data: Encrypted bytes in the format IV + ciphertext.
    :return: Original plaintext bytes.
    """
    algo_cls, _, block_len = _ALGOS[algo]
    iv, ciphertext = data[:block_len], data[block_len:]
    decryptor = Cipher(algo_cls(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(block_len * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()