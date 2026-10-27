"""
ARP Spoofing Simulation module.
Simulates an attacker on VM 3 forging ARP information claiming Gateway IP -> Attacker MAC.
"""

from arp.message import create_arp_message
from arp.sender import encrypt_message, craft_scapy_packet
from keys.generate_keys import load_dsa_key, load_symmetric_key


def simulate_arp_spoofing(config, packet_handler=None):
    """
    Simulates an ARP Spoofing attack.
    Attacker attempts to link Gateway IP (192.168.56.1) to Attacker MAC (11:22:33:44:55:66).
    The attacker signs the forged message using attacker_private.pem, but claims key_id='gateway'.
    Since the receiver uses gateway_public.pem, signature verification fails.
    
    :param config: Configuration dictionary.
    :param packet_handler: Callback function receiving forged Scapy packet.
    :return: (forged_scapy_packet, logs: list)
    """
    logs = []
    def log(m): logs.append(m)

    gateway_ip = config.get("gateway_ip", "192.168.56.1")
    attacker_mac = config.get("attacker_mac", "11:22:33:44:55:66")
    target_ip = config.get("peer_ip", "192.168.56.20")
    target_mac = config.get("peer_mac", "08:00:27:AA:BB:CC")
    crypto_mode = config.get("crypto_mode", "secure").lower()
    keys_dir = config.get("keys_dir", "keys")

    log("[ATTACK] Crafting forged ARP response...")
    log(f"  Claiming: {gateway_ip} -> {attacker_mac}")

    # Step 1: Create forged ARP message object
    msg_obj = create_arp_message(
        sender_ip=gateway_ip,
        sender_mac=attacker_mac,
        target_ip=target_ip,
        target_mac=target_mac
    )

    # Step 2: Attacker signs forged message using attacker_private.pem
    attacker_priv_pem = load_dsa_key("attacker", "private", keys_dir)
    # Attacker sets key_id='gateway' to pretend the signature is from legitimate Gateway
    package_dict = msg_obj.build_signed_package(attacker_priv_pem, key_id="gateway", crypto_mode=crypto_mode)

    log("[ATTACK] Forged message signed with unauthorized attacker private key.")

    # Step 3: Encrypt forged payload
    sym_key = load_symmetric_key("aes" if crypto_mode == "secure" else "des", keys_dir)
    envelope_dict = encrypt_message(package_dict, sym_key, crypto_mode=crypto_mode)

    # Step 4: Craft Scapy packet
    pkt = craft_scapy_packet(envelope_dict, gateway_ip, attacker_mac, target_ip, target_mac)

    log("[ATTACK] Transmitting forged ARP packet...")
    if packet_handler:
        packet_handler(pkt)

    return pkt, logs
