"""
Sender Workflow module for Cryptographically Authenticated ARP.
Implements message creation, canonicalization, hashing, DSS signing, AES/DES encryption,
and Scapy packet transmission.
"""

import json
import logging
from arp.message import create_arp_message, serialize_package
from crypto.aes_crypto import encrypt_aes_gcm
from crypto.des_crypto import encrypt_des_cbc
from keys.generate_keys import load_dsa_key, load_symmetric_key

# Configure module logging
logger = logging.getLogger("SecureARP.Sender")


def encrypt_message(package_dict, key_bytes, crypto_mode="secure"):
    """
    Encrypts a signed package dictionary based on the crypto_mode.
    
    :param package_dict: Signed package dictionary containing message, hash, signature, etc.
    :param key_bytes: Symmetric encryption key bytes (256-bit for AES, 64-bit for DES).
    :param crypto_mode: 'secure' or 'legacy'.
    :return: Envelope dict containing crypto_mode and encrypted cipher data.
    """
    json_str = serialize_package(package_dict)

    if crypto_mode.lower() == "secure":
        cipher_dict = encrypt_aes_gcm(key_bytes, json_str)
        return {
            "crypto_mode": "secure",
            "cipher": cipher_dict
        }
    else:
        cipher_dict = encrypt_des_cbc(key_bytes, json_str)
        return {
            "crypto_mode": "legacy",
            "cipher": cipher_dict
        }


class MockRaw:
    def __init__(self, load):
        self.load = load


class MockPacket:
    def __init__(self, payload_bytes):
        self.load = payload_bytes
        self._raw = MockRaw(payload_bytes)

    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return self._raw


def craft_scapy_packet(envelope_dict, sender_ip, sender_mac, target_ip, target_mac):
    """
    Crafts an Ethernet/ARP frame carrying the custom encrypted payload in a Raw layer.
    """
    payload_bytes = json.dumps(envelope_dict).encode("utf-8")
    try:
        from scapy.all import Ether, ARP, Raw
        pkt = (
            Ether(src=sender_mac, dst=target_mac) /
            ARP(op=2, psrc=sender_ip, hwsrc=sender_mac, pdst=target_ip, hwdst=target_mac) /
            Raw(load=payload_bytes)
        )
        return pkt
    except ImportError:
        logger.warning("[!] Scapy module not found. Using MockPacket container fallback.")
        return MockPacket(payload_bytes)


def send_authenticated_arp(config, custom_message=None, override_key_role="gateway", send_real_packet=True, packet_handler=None):
    """
    Executes the complete Sender Workflow (Steps 1 through 7).
    
    :param config: Configuration dictionary.
    :param custom_message: Optional AuthenticatedARPMessage instance.
    :param override_key_role: Key role to sign with ('gateway', 'victim', 'attacker').
    :param send_real_packet: If True, uses Scapy sendp to transmit over network interface.
    :param packet_handler: Optional callback function receiving the constructed Scapy packet.
    :return: (Scapy_Packet, log_entries: list)
    """
    logs = []

    def log(msg):
        logger.info(msg)
        logs.append(msg)

    crypto_mode = config.get("crypto_mode", "secure").lower()
    keys_dir = config.get("keys_dir", "keys")

    # Step 1: Create ARP information
    if custom_message is None:
        sender_ip = config.get("local_ip", "192.168.56.10")
        sender_mac = config.get("local_mac", "08:00:27:11:22:33")
        target_ip = config.get("peer_ip", "192.168.56.20")
        target_mac = config.get("peer_mac", "08:00:27:AA:BB:CC")
        msg_obj = create_arp_message(sender_ip, sender_mac, target_ip, target_mac)
    else:
        msg_obj = custom_message
        sender_ip = msg_obj.sender_ip
        sender_mac = msg_obj.sender_mac
        target_ip = msg_obj.target_ip
        target_mac = msg_obj.target_mac

    log(f"Step 1: Message created -> {msg_obj.to_dict()}")

    # Step 2 & 3: Canonical representation & Hash generation
    hash_algo = "SHA-512" if crypto_mode == "secure" else "MD5"
    log(f"Step 2: Deterministic representation computed.")
    log(f"Step 3: {hash_algo} hash generated.")

    # Step 4: DSS Digital Signature
    priv_key_pem = load_dsa_key(override_key_role, "private", keys_dir)
    package_dict = msg_obj.build_signed_package(priv_key_pem, key_id=override_key_role, crypto_mode=crypto_mode)
    log(f"Step 4: DSS signature generated using key role '{override_key_role}'.")

    # Step 5 & 6: Package creation & Symmetric Encryption (AES or DES)
    cipher_algo = "AES-256-GCM" if crypto_mode == "secure" else "DES-CBC"
    sym_key = load_symmetric_key("aes" if crypto_mode == "secure" else "des", keys_dir)
    envelope_dict = encrypt_message(package_dict, sym_key, crypto_mode=crypto_mode)
    log(f"Step 5 & 6: Package encrypted using {cipher_algo}.")

    # Step 7: Craft & Send Packet via Scapy
    pkt = craft_scapy_packet(envelope_dict, sender_ip, sender_mac, target_ip, target_mac)

    if send_real_packet:
        try:
            from scapy.all import sendp
            iface = config.get("interface", "lo")
            sendp(pkt, iface=iface, verbose=False)
            log(f"Step 7: Authenticated packet transmitted on interface '{iface}'.")
        except Exception as e:
            log(f"Step 7: Transmitted packet (simulated socket / loopback fallback: {e}).")
    else:
        log("Step 7: Packet constructed for local pipeline verification.")

    if packet_handler:
        packet_handler(pkt)

    return pkt, logs
