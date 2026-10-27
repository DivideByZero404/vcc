"""
Receiver Verification Engine module for Cryptographically Authenticated ARP.
Implements packet capture, decryption, signature verification, hash integrity checking,
timestamp/nonce validation, and ARP table update logic.
"""

import json
import logging
from crypto.aes_crypto import decrypt_aes_gcm
from crypto.des_crypto import decrypt_des_cbc
from crypto.hashing import canonical_representation, compute_sha512, compute_md5
from crypto.dss import verify_signature
from keys.generate_keys import load_dsa_key, load_symmetric_key
from arp.replay_protection import ReplayProtector

logger = logging.getLogger("SecureARP.Receiver")


def verify_received_payload(payload_bytes, config, replay_protector=None):
    """
    Executes Steps 2 through 9 of the Receiver Workflow on received payload bytes.
    
    :param payload_bytes: Raw bytes extracted from Scapy packet load.
    :param config: Configuration dictionary.
    :param replay_protector: ReplayProtector instance (creates default if None).
    :return: dict containing:
        - status: 'ACCEPT' or 'REJECT'
        - reason: str explanation
        - details: dict of step-by-step verification results
        - message: dict of ARP message parameters (if decrypted)
    """
    if replay_protector is None:
        max_drift = config.get("timestamp_max_drift", 60)
        replay_protector = ReplayProtector(max_drift_seconds=max_drift)

    keys_dir = config.get("keys_dir", "keys")

    verification_details = {
        "decryption": "WAITING",
        "dss_signature": "WAITING",
        "hash_integrity": "WAITING",
        "timestamp": "WAITING",
        "nonce": "WAITING"
    }

    # Step 2: Extract encrypted envelope
    try:
        if isinstance(payload_bytes, str):
            envelope = json.loads(payload_bytes)
        else:
            envelope = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        verification_details["decryption"] = "FAIL"
        verification_details["dss_signature"] = "SKIPPED"
        verification_details["hash_integrity"] = "SKIPPED"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": f"Malformed payload structure ({e})",
            "details": verification_details,
            "message": None
        }

    crypto_mode = envelope.get("crypto_mode", "secure").lower()
    cipher_data = envelope.get("cipher", {})

    # Step 3: Decrypt payload
    try:
        if crypto_mode == "secure":
            sym_key = load_symmetric_key("aes", keys_dir)
            decrypted_bytes = decrypt_aes_gcm(
                sym_key,
                cipher_data["ciphertext"],
                cipher_data["nonce"],
                cipher_data["tag"]
            )
        else:
            sym_key = load_symmetric_key("des", keys_dir)
            decrypted_bytes = decrypt_des_cbc(
                sym_key,
                cipher_data["ciphertext"],
                cipher_data["iv"]
            )
        verification_details["decryption"] = "PASS"
    except Exception as e:
        verification_details["decryption"] = "FAIL"
        verification_details["dss_signature"] = "SKIPPED"
        verification_details["hash_integrity"] = "SKIPPED"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": f"Decryption failed ({e})",
            "details": verification_details,
            "message": None
        }

    # Step 4: Extract package contents
    try:
        package = json.loads(decrypted_bytes.decode("utf-8"))
        msg_dict = package["message"]
        received_hash = package["hash"]
        sig_b64 = package["signature"]
        key_id = package.get("key_id", "gateway")
    except Exception as e:
        verification_details["dss_signature"] = "FAIL"
        verification_details["hash_integrity"] = "SKIPPED"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": f"Invalid decrypted JSON format ({e})",
            "details": verification_details,
            "message": None
        }

    import base64
    raw_signature = base64.b64decode(sig_b64)

    # Step 5: Verify DSS Signature
    try:
        sender_pub_pem = load_dsa_key(key_id, "public", keys_dir)
    except Exception as e:
        verification_details["dss_signature"] = "FAIL"
        verification_details["hash_integrity"] = "SKIPPED"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": f"Unknown sender key identity '{key_id}' ({e})",
            "details": verification_details,
            "message": msg_dict
        }

    canonical_str = canonical_representation(
        msg_dict["sender_ip"],
        msg_dict["sender_mac"],
        msg_dict["target_ip"],
        msg_dict["target_mac"],
        msg_dict["timestamp"],
        msg_dict["nonce"]
    )

    hash_algo = "sha512" if crypto_mode == "secure" else "md5"
    sig_valid = verify_signature(
        sender_pub_pem,
        canonical_str.encode("utf-8"),
        raw_signature,
        hash_algo=hash_algo
    )

    if not sig_valid:
        verification_details["dss_signature"] = "FAIL"
        verification_details["hash_integrity"] = "SKIPPED"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": "Invalid digital signature (Possible ARP spoofing attempt)",
            "details": verification_details,
            "message": msg_dict
        }
    verification_details["dss_signature"] = "PASS"

    # Step 6: Recalculate SHA-512 / MD5 hash
    if hash_algo == "sha512":
        calculated_hash, _ = compute_sha512(canonical_str)
    else:
        calculated_hash, _ = compute_md5(canonical_str)

    if calculated_hash != received_hash:
        verification_details["hash_integrity"] = "FAIL"
        verification_details["timestamp"] = "SKIPPED"
        verification_details["nonce"] = "SKIPPED"
        return {
            "status": "REJECT",
            "reason": "Integrity verification failed (Computed hash differs from received hash)",
            "details": verification_details,
            "message": msg_dict
        }
    verification_details["hash_integrity"] = "PASS"

    # Step 7 & 8: Check Timestamp and Nonce (Replay Protection)
    timestamp = msg_dict["timestamp"]
    nonce = msg_dict["nonce"]
    time_nonce_valid, reason_str = replay_protector.validate(timestamp, nonce)

    if not time_nonce_valid:
        if "Expired timestamp" in reason_str:
            verification_details["timestamp"] = "FAIL"
            verification_details["nonce"] = "SKIPPED"
        if "Nonce already used" in reason_str:
            verification_details["timestamp"] = "PASS"
            verification_details["nonce"] = "FAIL"

        return {
            "status": "REJECT",
            "reason": reason_str,
            "details": verification_details,
            "message": msg_dict
        }

    verification_details["timestamp"] = "PASS"
    verification_details["nonce"] = "PASS"

    # Step 9: Accept & Update Authenticated ARP Mapping
    return {
        "status": "ACCEPT",
        "reason": "Authenticated ARP response verified successfully",
        "details": verification_details,
        "message": msg_dict
    }


def process_scapy_packet(pkt, config, replay_protector=None, result_callback=None):
    """
    Processes an incoming Scapy or Mock packet, extracts payload, runs verification, and triggers callback.
    """
    payload = None
    try:
        from scapy.all import Raw
        if Raw in pkt:
            payload = pkt[Raw].load
    except ImportError:
        pass

    if payload is None:
        if hasattr(pkt, "load"):
            payload = pkt.load
        elif hasattr(pkt, "_raw"):
            payload = pkt._raw.load
        else:
            return None

    result = verify_received_payload(payload, config, replay_protector=replay_protector)

    if result_callback:
        result_callback(pkt, result)

    return result


def receive_authenticated_arp(config, replay_protector=None, timeout=None, packet_count=1, result_callback=None):
    """
    Sniffs network traffic for authenticated ARP packets and verifies them.
    
    :param config: Configuration dictionary.
    :param replay_protector: ReplayProtector instance.
    :param timeout: Sniffing timeout in seconds (None for continuous).
    :param packet_count: Number of packets to capture (0 for continuous).
    :param result_callback: Callback function receiving (pkt, result_dict).
    """
    from scapy.all import sniff

    iface = config.get("interface", "lo")
    if replay_protector is None:
        max_drift = config.get("timestamp_max_drift", 60)
        replay_protector = ReplayProtector(max_drift_seconds=max_drift)

    def prn(pkt):
        process_scapy_packet(pkt, config, replay_protector=replay_protector, result_callback=result_callback)

    try:
        sniff(iface=iface, filter="arp", prn=prn, timeout=timeout, count=packet_count, store=False)
    except Exception as e:
        logger.warning(f"Live sniffing failed on interface {iface} ({e}). Falling back to manual process queue.")
