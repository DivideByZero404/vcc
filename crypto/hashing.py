"""
Hashing module for Cryptographically Authenticated ARP.
Provides SHA-512 (Secure Mode) and MD5 (Legacy Mode) functions,
along with canonical ARP message representation.
"""

from Crypto.Hash import SHA512, MD5


def canonical_representation(sender_ip, sender_mac, target_ip, target_mac, timestamp, nonce):
    """
    Constructs the canonical string representation of an ARP message.
    Format: sender_ip|sender_mac|target_ip|target_mac|timestamp|nonce
    """
    return f"{sender_ip}|{sender_mac}|{target_ip}|{target_mac}|{timestamp}|{nonce}"


def compute_sha512(data):
    """
    Computes SHA-512 digest of data (str or bytes).
    Returns (hex_digest_str, raw_digest_bytes).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = SHA512.new(data)
    return h.hexdigest(), h.digest()


def compute_md5(data):
    """
    Computes MD5 digest of data (str or bytes).
    Returns (hex_digest_str, raw_digest_bytes).
    Note: MD5 is cryptographically broken/obsolete and used ONLY for legacy mode comparison.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = MD5.new(data)
    return h.hexdigest(), h.digest()
