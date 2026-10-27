"""
Packet Tampering Simulation module.
Modifies message parameters (sender_mac, sender_ip, target_ip, target_mac, timestamp)
after signature generation, demonstrating SHA-512 and DSS failure.
"""

from arp.message import create_arp_message
from arp.sender import encrypt_message, craft_scapy_packet
from keys.generate_keys import load_dsa_key, load_symmetric_key


def simulate_tampering_attack(config, field_to_tamper="sender_mac", custom_value="11:22:33:44:55:66", packet_handler=None):
    """
    Simulates a Packet Tampering attack.
    Generates a valid signed package, then modifies one of the fields in the message dictionary
    without updating the digital signature or hash digest.
    
    :param config: Configuration dictionary.
    :param field_to_tamper: Field to tamper with ('sender_mac', 'sender_ip', 'target_ip', 'timestamp').
    :param custom_value: New tampered value.
    :param packet_handler: Callback receiving tampered Scapy packet.
    :return: (tampered_scapy_packet, logs: list)
    """
    logs = []
    def log(m): logs.append(m)

    sender_ip = config.get("local_ip", "192.168.56.10")
    sender_mac = config.get("local_mac", "08:00:27:11:22:33")
    target_ip = config.get("peer_ip", "192.168.56.20")
    target_mac = config.get("peer_mac", "08:00:27:AA:BB:CC")
    crypto_mode = config.get("crypto_mode", "secure").lower()
    keys_dir = config.get("keys_dir", "keys")

    log("[ATTACK] Creating valid ARP message and computing DSS signature...")

    # Step 1: Create message & sign correctly with Gateway private key
    msg_obj = create_arp_message(sender_ip, sender_mac, target_ip, target_mac)
    gateway_priv_pem = load_dsa_key("gateway", "private", keys_dir)
    package_dict = msg_obj.build_signed_package(gateway_priv_pem, key_id="gateway", crypto_mode=crypto_mode)

    # Step 2: Tamper with message parameter AFTER signature generation
    log(f"[ATTACK] Tampering with field '{field_to_tamper}' -> set to '{custom_value}' post-signature.")
    package_dict["message"][field_to_tamper] = custom_value

    # Step 3: Encrypt tampered package
    sym_key = load_symmetric_key("aes" if crypto_mode == "secure" else "des", keys_dir)
    envelope_dict = encrypt_message(package_dict, sym_key, crypto_mode=crypto_mode)

    # Step 4: Craft Scapy packet
    tampered_mac = custom_value if field_to_tamper == "sender_mac" else sender_mac
    tampered_ip = custom_value if field_to_tamper == "sender_ip" else sender_ip
    pkt = craft_scapy_packet(envelope_dict, tampered_ip, tampered_mac, target_ip, target_mac)

    log("[ATTACK] Transmitting tampered packet...")
    if packet_handler:
        packet_handler(pkt)

    return pkt, logs
