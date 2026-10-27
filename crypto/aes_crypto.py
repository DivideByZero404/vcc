"""
AES Encryption module for Cryptographically Authenticated ARP (Secure Mode).
Implements AES-256-GCM for authenticated encryption and confidentiality.
"""

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt_aes_gcm(key_bytes, plaintext):
    """
    Encrypts plaintext using AES-256-GCM.
    
    :param key_bytes: 32-byte (256-bit) secret key.
    :param plaintext: Plaintext string or bytes.
    :return: dict with base64 encoded ciphertext, nonce, and tag.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8")
    }


def decrypt_aes_gcm(key_bytes, ciphertext_b64, nonce_b64, tag_b64):
    """
    Decrypts AES-256-GCM encrypted payload.
    
    :param key_bytes: 32-byte secret key.
    :param ciphertext_b64: Base64 encoded ciphertext string.
    :param nonce_b64: Base64 encoded nonce string.
    :param tag_b64: Base64 encoded authentication tag string.
    :return: Decrypted plaintext bytes if authentication passes.
    :raises ValueError: If MAC tag validation or decryption fails.
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)

    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
