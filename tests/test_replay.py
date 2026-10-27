"""
Unit and integration tests for Replay Protection and Timestamp drift.
Covers Test 5 (Expired Timestamp) and Test 6 (Reused Nonce Replay).
"""

import os
import time
import unittest
from scapy.all import Raw
from config import load_config
from arp.message import create_arp_message
from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from attacks.replay import simulate_replay_attack
from keys.generate_keys import generate_all_keys

TEST_KEYS_DIR = os.path.join(os.path.dirname(__file__), "test_keys")


class TestReplayProtection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_all_keys(target_dir=TEST_KEYS_DIR)
        cls.config = load_config()
        cls.config["keys_dir"] = TEST_KEYS_DIR
        cls.config["crypto_mode"] = "secure"

    def setUp(self):
        self.replay_protector = ReplayProtector(max_drift_seconds=60)

    def test_5_expired_timestamp(self):
        """Test 5: Message with stale timestamp outside drift window -> Expected: FAIL"""
        stale_time = time.time() - 300  # 5 minutes old
        stale_msg = create_arp_message(
            sender_ip="192.168.56.10",
            sender_mac="08:00:27:11:22:33",
            target_ip="192.168.56.20",
            target_mac="08:00:27:AA:BB:CC",
            timestamp=stale_time
        )
        pkt, logs = send_authenticated_arp(self.config, custom_message=stale_msg, send_real_packet=False)
        payload = pkt[Raw].load
        res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)

        self.assertEqual(res["status"], "REJECT")
        self.assertIn("Expired timestamp", res["reason"])
        self.assertEqual(res["details"]["timestamp"], "FAIL")

    def test_6_reused_nonce(self):
        """Test 6: Duplicate packet retransmitted (Replay Attack) -> Expected: FAIL"""
        pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load

        # First reception -> ACCEPT
        res1 = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
        self.assertEqual(res1["status"], "ACCEPT")

        # Second reception of identical packet (Replay) -> REJECT
        res2 = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
        self.assertEqual(res2["status"], "REJECT")
        self.assertIn("Nonce already used", res2["reason"])
        self.assertEqual(res2["details"]["nonce"], "FAIL")


if __name__ == "__main__":
    unittest.main()
