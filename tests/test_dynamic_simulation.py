"""
Comprehensive automated tests for dynamic simulation, input validation,
attack counters, stream controls, and ARP cache protection.
"""

import os
import time
import unittest
from scapy.all import Raw
from config import load_config
from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from attacks.spoofing import simulate_arp_spoofing
from attacks.tampering import simulate_tampering_attack
from keys.generate_keys import generate_all_keys
from web_ui import (
    app,
    validate_ipv4,
    validate_mac,
    validate_nonce,
    validate_timestamp,
    execute_legitimate,
    execute_spoofing,
    execute_tampering,
    execute_replay,
    counters,
    arp_cache
)

TEST_KEYS_DIR = os.path.join(os.path.dirname(__file__), "test_keys")


class TestDynamicSimulationEnhancements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generate_all_keys(target_dir=TEST_KEYS_DIR)
        cls.config = load_config()
        cls.config["keys_dir"] = TEST_KEYS_DIR
        cls.config["crypto_mode"] = "secure"
        cls.client = app.test_client()

    def setUp(self):
        self.replay_protector = ReplayProtector(max_drift_seconds=60)
        # Reset counters and state before each test
        self.client.post("/api/reset_simulation")

    def test_validation_utilities(self):
        """Test IPv4, MAC, Nonce, and Timestamp validators"""
        # Valid cases
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertTrue(validate_ipv4("10.0.0.254"))
        self.assertTrue(validate_mac("08:00:27:11:22:33"))
        self.assertTrue(validate_mac("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(validate_nonce("156adce85310615e373d8ea44a84341b"))
        self.assertTrue(validate_timestamp(1700000000.123))
        self.assertTrue(validate_timestamp("1700000000.123"))

        # Invalid cases
        self.assertFalse(validate_ipv4("999.1.1.1"))
        self.assertFalse(validate_ipv4("invalid_ip"))
        self.assertFalse(validate_ipv4("192.168.1"))
        self.assertFalse(validate_mac("08:00:27:11:22"))
        self.assertFalse(validate_mac("NOT:A:MAC:ADDR:00:00"))
        self.assertFalse(validate_nonce("short"))
        self.assertFalse(validate_nonce("xyz_non_hex_character_token_1234"))
        self.assertFalse(validate_timestamp("not_a_number"))

    def test_dynamic_custom_sender_fields(self):
        """Test legitimate packet execution with dynamic custom IP and MAC"""
        custom_payload = {
            "sender_ip": "10.0.0.50",
            "sender_mac": "02:00:00:11:22:33",
            "target_ip": "10.0.0.1",
            "target_mac": "02:00:00:AA:BB:CC",
            "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        }
        res = self.client.post("/api/send_legitimate", json=custom_payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["result"]["status"], "ACCEPT")
        self.assertEqual(data["sender"]["sender_ip"], "10.0.0.50")
        self.assertEqual(data["sender"]["sender_mac"], "02:00:00:11:22:33")
        self.assertEqual(data["receiver"]["source_ip"], "10.0.0.50")
        self.assertEqual(data["receiver"]["source_mac"], "02:00:00:11:22:33")

        # Verify ARP cache was updated with the new dynamic binding
        cache_ips = [entry["ip"] for entry in data["arp_cache"]]
        self.assertIn("10.0.0.50", cache_ips)

    def test_malformed_input_rejection(self):
        """Test that malformed inputs are rejected with HTTP 400 and clear error messages"""
        bad_ip_payload = {
            "sender_ip": "999.999.999.999",
            "sender_mac": "08:00:27:11:22:33"
        }
        res = self.client.post("/api/send_legitimate", json=bad_ip_payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid IPv4 format", res.get_json()["error"])

        bad_mac_payload = {
            "sender_ip": "192.168.56.10",
            "sender_mac": "invalid_mac"
        }
        res = self.client.post("/api/send_legitimate", json=bad_mac_payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Invalid MAC address", res.get_json()["error"])

    def test_spoofing_defense_and_cache_protection(self):
        """Test that spoofing attacks increment counter and DO NOT poison the ARP cache"""
        initial_res = self.client.get("/api/status").get_json()
        initial_cache = initial_res["arp_cache"]

        spoof_payload = {
            "gateway_ip": "192.168.56.1",
            "attacker_mac": "DE:AD:BE:EF:00:01"
        }
        res = self.client.post("/api/simulate_spoofing", json=spoof_payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Decision must be REJECT
        self.assertEqual(data["result"]["status"], "REJECT")
        self.assertEqual(data["result"]["details"]["dss_signature"], "FAIL")

        # Gateway MAC in ARP cache MUST NOT be poisoned with DE:AD:BE:EF:00:01
        for entry in data["arp_cache"]:
            if entry["ip"] == "192.168.56.1":
                self.assertNotEqual(entry["mac"], "DE:AD:BE:EF:00:01")

        # Verify spoofing counter incremented
        status_data = self.client.get("/api/status").get_json()
        self.assertEqual(status_data["counters"]["spoofing"], 1)

    def test_packet_tampering_defense(self):
        """Test tampering simulation detection and verification failure"""
        tamper_payload = {
            "field_to_tamper": "sender_mac",
            "custom_value": "44:55:66:77:88:99"
        }
        res = self.client.post("/api/simulate_tampering", json=tamper_payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data["result"]["status"], "REJECT")
        self.assertEqual(data["result"]["details"]["dss_signature"], "FAIL")

        status_data = self.client.get("/api/status").get_json()
        self.assertEqual(status_data["counters"]["tampering"], 1)

    def test_replay_attack_detection(self):
        """Test replay simulation detects duplicate nonce and rejects packet"""
        # First send valid packet
        res1 = self.client.post("/api/send_legitimate", json={})
        self.assertEqual(res1.status_code, 200)

        # Now simulate replay
        res2 = self.client.post("/api/simulate_replay")
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()

        self.assertEqual(data2["result"]["status"], "REJECT")
        self.assertEqual(data2["result"]["details"]["nonce"], "FAIL")

        status_data = self.client.get("/api/status").get_json()
        self.assertEqual(status_data["counters"]["replay"], 1)

    def test_skipped_pipeline_stages_on_corrupt_ciphertext(self):
        """Test that unreached pipeline stages are marked as SKIPPED when decryption fails"""
        pkt, _ = send_authenticated_arp(self.config, send_real_packet=False)
        payload = pkt[Raw].load.decode("utf-8")
        corrupt_payload = payload.replace("cipher", "broken_cipher")

        result = verify_received_payload(corrupt_payload, self.config, replay_protector=self.replay_protector)
        self.assertEqual(result["status"], "REJECT")
        self.assertEqual(result["details"]["decryption"], "FAIL")
        self.assertEqual(result["details"]["dss_signature"], "SKIPPED")
        self.assertEqual(result["details"]["hash_integrity"], "SKIPPED")
        self.assertEqual(result["details"]["timestamp"], "SKIPPED")
        self.assertEqual(result["details"]["nonce"], "SKIPPED")

    def test_stream_controls_and_modes(self):
        """Test that stream can be configured, started, and stopped cleanly"""
        start_res = self.client.post("/api/start_stream", json={"interval": 1.0, "mode": "legitimate"})
        self.assertEqual(start_res.status_code, 200)
        start_data = start_res.get_json()
        self.assertTrue(start_data["live_stream_active"])
        self.assertEqual(start_data["live_stream_mode"], "legitimate")

        stop_res = self.client.post("/api/stop_stream")
        self.assertEqual(stop_res.status_code, 200)
        stop_data = stop_res.get_json()
        self.assertFalse(stop_data["live_stream_active"])

    def test_simulation_reset(self):
        """Test that reset endpoint clears counters, sequences, and restores baseline"""
        # Generate some activity
        self.client.post("/api/send_legitimate", json={})
        self.client.post("/api/simulate_spoofing", json={})

        # Call reset
        reset_res = self.client.post("/api/reset_simulation")
        self.assertEqual(reset_res.status_code, 200)
        data = reset_res.get_json()

        self.assertEqual(data["counters"]["valid"], 0)
        self.assertEqual(data["counters"]["rejected"], 0)
        self.assertEqual(data["counters"]["spoofing"], 0)
        self.assertEqual(data["seq_counter"], 0)


if __name__ == "__main__":
    unittest.main()

