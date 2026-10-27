"""
DES Encryption module for Cryptographically Authenticated ARP (Legacy Mode).
Implements DES-CBC with PKCS7 padding for educational weak mode demonstration.
"""

import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def encrypt_des_cbc(key_bytes, plaintext):
    """
    Encrypts plaintext using DES-CBC.
    
    :param key_bytes: 8-byte (64-bit) secret key (56 effective security bits).
    :param plaintext: Plaintext string or bytes.
    :return: dict with base64 encoded ciphertext and initialization vector (iv).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    # Key must be 8 bytes
    if len(key_bytes) != 8:
        key_bytes = key_bytes[:8].ljust(8, b"\x00")

    cipher = DES.new(key_bytes, DES.MODE_CBC)
    padded_plaintext = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "iv": base64.b64encode(cipher.iv).decode("utf-8")
    }


def decrypt_des_cbc(key_bytes, ciphertext_b64, iv_b64):
    """
    Decrypts DES-CBC encrypted payload.
    
    :param key_bytes: 8-byte secret key.
    :param ciphertext_b64: Base64 encoded ciphertext string.
    :param iv_b64: Base64 encoded IV string.
    :return: Decrypted plaintext bytes.
    :raises ValueError: If padding unpad or decryption fails.
    """
    if len(key_bytes) != 8:
        key_bytes = key_bytes[:8].ljust(8, b"\x00")

    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    decipher = DES.new(key_bytes, DES.MODE_CBC, iv=iv)
    padded_plaintext = decipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size)
    return plaintext
