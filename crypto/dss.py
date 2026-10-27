"""
DSS Digital Signature module for Cryptographically Authenticated ARP.
Uses PyCryptodome DSS with 2048-bit DSA keys for signing and verification.
"""

from Crypto.PublicKey import DSA
from Crypto.Hash import SHA512, MD5
from Crypto.Signature import DSS


def generate_signature(private_key_pem, message_bytes, hash_algo="sha512"):
    """
    Generates a DSS signature for message_bytes using a DSA private key.
    
    :param private_key_pem: PEM-encoded DSA private key bytes or str.
    :param message_bytes: Message bytes to sign.
    :param hash_algo: 'sha512' for Secure Mode or 'md5' for Legacy Mode.
    :return: Raw signature bytes.
    """
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    if isinstance(message_bytes, str):
        message_bytes = message_bytes.encode("utf-8")

    dsa_key = DSA.import_key(private_key_pem)

    if hash_algo.lower() == "sha512":
        h = SHA512.new(message_bytes)
        signer = DSS.new(dsa_key, "fips-186-3")
    elif hash_algo.lower() == "md5":
        h = MD5.new(message_bytes)
        # RFC 6979 mode allows MD5 signing for legacy educational mode without FIPS restriction
        signer = DSS.new(dsa_key, "deterministic-rfc6979")
    else:
        raise ValueError(f"Unsupported hash algorithm for DSS: {hash_algo}")

    signature = signer.sign(h)
    return signature


def verify_signature(public_key_pem, message_bytes, signature_bytes, hash_algo="sha512"):
    """
    Verifies a DSS signature for message_bytes using a DSA public key.
    
    :param public_key_pem: PEM-encoded DSA public key bytes or str.
    :param message_bytes: Received message bytes.
    :param signature_bytes: Signature bytes to verify.
    :param hash_algo: 'sha512' for Secure Mode or 'md5' for Legacy Mode.
    :return: True if signature is valid, False otherwise.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    if isinstance(message_bytes, str):
        message_bytes = message_bytes.encode("utf-8")

    try:
        dsa_key = DSA.import_key(public_key_pem)

        if hash_algo.lower() == "sha512":
            h = SHA512.new(message_bytes)
            verifier = DSS.new(dsa_key, "fips-186-3")
        elif hash_algo.lower() == "md5":
            h = MD5.new(message_bytes)
            verifier = DSS.new(dsa_key, "deterministic-rfc6979")
        else:
            return False

        verifier.verify(h, signature_bytes)
        return True
    except (ValueError, TypeError, KeyError) as e:
        # Signature verification failed
        return False
