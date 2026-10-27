"""
Replay Attack Simulation module.
Captures a valid authenticated ARP message and retransmits it to trigger nonce reuse rejection.
"""

from arp.sender import send_authenticated_arp


def simulate_replay_attack(config, original_pkt=None, packet_handler=None):
    """
    Simulates a Replay Attack.
    Generates a valid authenticated ARP message (or uses an existing valid packet)
    and retransmits it a second time.
    
    :param config: Configuration dictionary.
    :param original_pkt: Optional existing Scapy packet to replay.
    :param packet_handler: Callback receiving replayed Scapy packet.
    :return: (replayed_scapy_packet, logs: list)
    """
    logs = []
    def log(m): logs.append(m)

    log("[ATTACK] Initiating Replay Attack simulation...")

    if original_pkt is None:
        log("[ATTACK] Generating initial valid packet for replay capture...")
        original_pkt, _ = send_authenticated_arp(config, send_real_packet=False)

    log("[ATTACK] Intercepted valid ARP payload. Re-transmitting duplicate frame...")

    if packet_handler:
        packet_handler(original_pkt)

    return original_pkt, logs
