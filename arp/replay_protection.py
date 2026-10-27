"""
Replay Protection module for Cryptographically Authenticated ARP.
Tracks nonces and enforces timestamp validity windows to prevent replay attacks.
"""

import time


class ReplayProtector:
    def __init__(self, max_drift_seconds=60):
        self.max_drift_seconds = max_drift_seconds
        self.seen_nonces = set()

    def validate(self, timestamp, nonce, current_time=None):
        """
        Validates timestamp freshness and nonce uniqueness.
        
        :param timestamp: Float/int timestamp from received message.
        :param nonce: String nonce from received message.
        :param current_time: Optional override for current system time (useful for unit tests).
        :return: (is_valid: bool, reason: str)
        """
        if current_time is None:
            current_time = time.time()

        # 1. Timestamp Freshness Check
        time_diff = abs(current_time - timestamp)
        if time_diff > self.max_drift_seconds:
            return False, f"Expired timestamp (drift = {round(time_diff, 2)}s, max allowed = {self.max_drift_seconds}s)"

        # 2. Nonce Uniqueness Check (Replay Prevention)
        if nonce in self.seen_nonces:
            return False, f"Nonce already used: '{nonce}' (Replay Attack Detected)"

        # Mark nonce as seen
        self.seen_nonces.add(nonce)

        # Optional: cleanup nonces if set grows too large (prevent memory leak)
        if len(self.seen_nonces) > 10000:
            self.seen_nonces.clear()

        return True, "Timestamp and Nonce verified"

    def clear(self):
        """Clears the seen nonce cache."""
        self.seen_nonces.clear()
