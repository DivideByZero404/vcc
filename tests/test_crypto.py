"""
Unit tests for Cryptographic primitives (SHA-512, MD5, DSS, AES-GCM, DES-CBC).
"""

import os
import unittest
from crypto.hashing import compute_sha512, compute_md5, canonical_representation
from crypto.dss import generate_signature, verify_signature
from crypto.aes_crypto import encrypt_aes_gcm, decrypt_aes_gcm
from crypto.des_crypto import encrypt_des_cbc, decrypt_des_cbc
from keys.generate_keys import generate_all_keys, load_dsa_key, load_symmetric_key

TEST_KEYS_DIR = os.path.join(os.path.dirname(__file__), "test_keys")


class TestCryptographicPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_all_keys(target_dir=TEST_KEYS_DIR)

    def test_canonical_representation(self):
        repr_str = canonical_representation("192.168.56.10", "08:00:27:11:22:33", "192.168.56.20", "08:00:27:AA:BB:CC", 1700000000.0, "abc123nonce")
        expected = "192.168.56.10|08:00:27:11:22:33|192.168.56.20|08:00:27:AA:BB:CC|1700000000.0|abc123nonce"
        self.assertEqual(repr_str, expected)

    def test_sha512_and_md5_hashing(self):
        msg = "test_canonical_string"
        hex_sha, raw_sha = compute_sha512(msg)
        hex_md5, raw_md5 = compute_md5(msg)

        self.assertEqual(len(hex_sha), 128)  # SHA-512 hex length
        self.assertEqual(len(hex_md5), 32)   # MD5 hex length
        self.assertNotEqual(hex_sha, hex_md5)

    def test_dss_signature_pass_and_fail(self):
        priv_pem = load_dsa_key("gateway", "private", TEST_KEYS_DIR)
        pub_pem = load_dsa_key("gateway", "public", TEST_KEYS_DIR)
        wrong_pub_pem = load_dsa_key("attacker", "public", TEST_KEYS_DIR)

        msg_bytes = b"canonical_message_content"
        sig = generate_signature(priv_pem, msg_bytes, hash_algo="sha512")

        # Valid signature verification -> True
        self.assertTrue(verify_signature(pub_pem, msg_bytes, sig, hash_algo="sha512"))

        # Wrong public key -> False
        self.assertFalse(verify_signature(wrong_pub_pem, msg_bytes, sig, hash_algo="sha512"))

        # Tampered message -> False
        self.assertFalse(verify_signature(pub_pem, b"tampered_message_content", sig, hash_algo="sha512"))

    def test_aes_gcm_encrypt_decrypt(self):
        aes_key = load_symmetric_key("aes", TEST_KEYS_DIR)
        plaintext = b"Sensitive ARP Information Package"

        enc_dict = encrypt_aes_gcm(aes_key, plaintext)
        decrypted = decrypt_aes_gcm(aes_key, enc_dict["ciphertext"], enc_dict["nonce"], enc_dict["tag"])
        self.assertEqual(decrypted, plaintext)

        # Tampered ciphertext -> ValueError exception
        bad_ciphertext = "A" + enc_dict["ciphertext"][1:]
        with self.assertRaises(ValueError):
            decrypt_aes_gcm(aes_key, bad_ciphertext, enc_dict["nonce"], enc_dict["tag"])

    def test_des_cbc_encrypt_decrypt(self):
        des_key = load_symmetric_key("des", TEST_KEYS_DIR)
        plaintext = b"Legacy ARP Payload"

        enc_dict = encrypt_des_cbc(des_key, plaintext)
        decrypted = decrypt_des_cbc(des_key, enc_dict["ciphertext"], enc_dict["iv"])
        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
