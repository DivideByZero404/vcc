"""
Attacks package containing ARP Spoofing, Replay Attack, and Packet Tampering simulation modules.
"""

from .spoofing import simulate_arp_spoofing
from .replay import simulate_replay_attack
from .tampering import simulate_tampering_attack

__all__ = [
    "simulate_arp_spoofing",
    "simulate_replay_attack",
    "simulate_tampering_attack",
]
