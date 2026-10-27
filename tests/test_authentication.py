"""
Unit and integration tests for Authentication and Integrity verification.
Covers Test 1 (Valid), Test 2 (Modified MAC), Test 3 (Modified IP),
Test 4 (Invalid Signature), and Test 7 (Modified Ciphertext).
"""

import os
import unittest
from scapy.all import Raw
from config import load_config
from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from attacks.spoofing import simulate_arp_spoofing
from attacks.tampering import simulate_tampering_attack
from keys.generate_keys import generate_all_keys

TEST_KEYS_DIR = os.path.join(os.path.dirname(__file__), "test_keys")


class TestAuthenticationPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_all_keys(target_dir=TEST_KEYS_DIR)
        cls.config = load_config()
        cls.config["keys_dir"] = TEST_KEYS_DIR
        cls.config["crypto_mode"] = "secure"

    def setUp(self):
        self.replay_protector = ReplayProtector(max_drift_seconds=60)

    def test_1_valid_message(self):
        """Test 1: Valid authenticated ARP message -> Expected: PASS"""
        pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load
        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "ACCEPT")
        self.assertEqual(res["details"]["dss_signature"], "PASS")
        self.assertEqual(res["details"]["hash_integrity"], "PASS")

    def test_2_modified_sender_mac(self):
        """Test 2: Tampered sender MAC post-signature -> Expected: FAIL"""
        pkt, logs = simulate_tampering_attack(
            self.config,
            field_to_tamper="sender_mac",
            custom_value="11:22:33:44:55:66"
        )
        payload = pkt[Raw].load
        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "REJECT")
        self.assertEqual(res["details"]["dss_signature"], "FAIL")

    def test_3_modified_sender_ip(self):
        """Test 3: Tampered sender IP post-signature -> Expected: FAIL"""
        pkt, logs = simulate_tampering_attack(
            self.config,
            field_to_tamper="sender_ip",
            custom_value="10.0.0.1"
        )
        payload = pkt[Raw].load
        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "REJECT")
        self.assertEqual(res["details"]["dss_signature"], "FAIL")

    def test_4_invalid_signature(self):
        """Test 4: ARP Spoofing with unauthorized attacker signature -> Expected: FAIL"""
        pkt, logs = simulate_arp_spoofing(self.config)
        payload = pkt[Raw].load
        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "REJECT")
        self.assertIn("Invalid digital signature", res["reason"])

    def test_7_modified_ciphertext(self):
        """Test 7: Corrupted encrypted payload -> Expected: FAIL (Decryption Error)"""
        pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load.decode("utf-8")

        # Corrupt ciphertext substring
        tampered_payload = payload.replace("cipher", "broken_cipher")
        res = verify_received_payload(tampered_payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "REJECT")
        self.assertEqual(res["details"]["decryption"], "FAIL")


if __name__ == "__main__":
    unittest.main()
