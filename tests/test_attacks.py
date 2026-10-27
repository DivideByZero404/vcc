"""
Unit and integration tests for Legacy / Weak Mode and Attack Simulations.
Covers Test 8 (Legacy MD5) and Test 9 (Legacy DES).
"""

import os
import unittest
from scapy.all import Raw
from config import load_config
from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from keys.generate_keys import generate_all_keys

TEST_KEYS_DIR = os.path.join(os.path.dirname(__file__), "test_keys")


class TestLegacyModeAndAttacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_all_keys(target_dir=TEST_KEYS_DIR)
        cls.config = load_config()
        cls.config["keys_dir"] = TEST_KEYS_DIR

    def setUp(self):
        self.replay_protector = ReplayProtector(max_drift_seconds=60)

    def test_8_legacy_md5_mode(self):
        """Test 8: Legacy Mode using MD5 hashing -> Demonstrates legacy hash pipeline"""
        self.config["crypto_mode"] = "legacy"
        pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load.decode("utf-8")

        self.assertIn('"crypto_mode": "legacy"', payload)

        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
        self.assertEqual(res["status"], "ACCEPT")
        self.assertEqual(res["details"]["dss_signature"], "PASS")

    def test_9_legacy_des_mode(self):
        """Test 9: Legacy Mode using DES-CBC encryption -> Demonstrates legacy cipher envelope"""
        self.config["crypto_mode"] = "legacy"
        pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load.decode("utf-8")

        # Verify envelope structure uses DES CBC 'iv' key rather than GCM 'tag'
        self.assertIn('"iv"', payload)
        self.assertNotIn('"tag"', payload)

        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
        self.assertEqual(res["status"], "ACCEPT")
        self.assertEqual(res["details"]["decryption"], "PASS")


if __name__ == "__main__":
    unittest.main()
