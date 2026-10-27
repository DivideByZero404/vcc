"""
Message definition for Cryptographically Authenticated ARP.
Provides data structures and JSON serialization/deserialization utilities.
"""

import json
import time
import secrets
import base64
from crypto.hashing import canonical_representation, compute_sha512, compute_md5
from crypto.dss import generate_signature, verify_signature


class AuthenticatedARPMessage:
    def __init__(self, sender_ip, sender_mac, target_ip, target_mac, timestamp=None, nonce=None):
        self.sender_ip = sender_ip
        self.sender_mac = sender_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.timestamp = timestamp if timestamp is not None else round(time.time(), 3)
        self.nonce = nonce if nonce is not None else secrets.token_hex(16)

    def to_dict(self):
        return {
            "sender_ip": self.sender_ip,
            "sender_mac": self.sender_mac,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }

    def canonical(self):
        """Returns the canonical string representation for cryptographic hashing."""
        return canonical_representation(
            self.sender_ip,
            self.sender_mac,
            self.target_ip,
            self.target_mac,
            self.timestamp,
            self.nonce
        )

    def build_signed_package(self, private_key_pem, key_id="gateway", crypto_mode="secure"):
        """
        Hashes canonical string, signs with DSS, and returns the package dictionary.
        """
        canonical_str = self.canonical()
        hash_algo = "sha512" if crypto_mode.lower() == "secure" else "md5"

        if hash_algo == "sha512":
            hex_digest, _ = compute_sha512(canonical_str)
        else:
            hex_digest, _ = compute_md5(canonical_str)

        raw_sig = generate_signature(private_key_pem, canonical_str.encode("utf-8"), hash_algo=hash_algo)
        sig_b64 = base64.b64encode(raw_sig).decode("utf-8")

        return {
            "message": self.to_dict(),
            "hash": hex_digest,
            "signature": sig_b64,
            "key_id": key_id,
            "crypto_mode": crypto_mode
        }


def create_arp_message(sender_ip, sender_mac, target_ip, target_mac, timestamp=None, nonce=None):
    """Factory function to instantiate AuthenticatedARPMessage."""
    return AuthenticatedARPMessage(sender_ip, sender_mac, target_ip, target_mac, timestamp, nonce)


def serialize_package(package_dict):
    """Converts a package dictionary to a JSON string."""
    return json.dumps(package_dict)


def deserialize_package(json_str):
    """Parses a JSON string into a package dictionary."""
    return json.loads(json_str)
