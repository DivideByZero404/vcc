"""
Flask-based Web UI Server for Cryptographically Authenticated ARP.
Provides Multi-Role Interactive Simulation (Sender Gateway, Attacker Node, Verifier Host).
Supports dynamic real-time payload typing, on-the-fly hash computation, input validation,
configurable traffic generation, and an enterprise light-theme dashboard.
"""

import time
import json
import random
import re
import webbrowser
import threading
from flask import Flask, render_template, jsonify, request
from config import load_config
from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from attacks.spoofing import simulate_arp_spoofing
from attacks.replay import simulate_replay_attack
from attacks.tampering import simulate_tampering_attack
from keys.generate_keys import generate_all_keys
from crypto.hashing import canonical_representation, compute_sha512, compute_md5

app = Flask(__name__)

# State management
config = load_config()
crypto_mode = config.get("crypto_mode", "secure").lower()
replay_protector = ReplayProtector(max_drift_seconds=config.get("timestamp_max_drift", 60))

last_valid_packet = None
logs_buffer = []

# Dynamic Stream State & Sequence Tracking
live_stream_active = False
live_stream_interval = 2.0  # seconds between dynamic packets
live_stream_mode = "legitimate"  # 'legitimate', 'mixed', 'spoofing', 'tampering', 'replay'
stream_thread = None

seq_counter = 0
packet_history = []

counters = {
    "valid": 0,
    "rejected": 0,
    "spoofing": 0,
    "replay": 0,
    "tampering": 0
}

latest_pipeline = {
    "decryption": "WAITING",
    "dss_signature": "WAITING",
    "hash_integrity": "WAITING",
    "timestamp": "WAITING",
    "nonce": "WAITING"
}

# Role-specific live states
arp_cache = [
    {
        "ip": config.get("gateway_ip", "192.168.56.1"),
        "mac": config.get("gateway_mac", "AA:BB:CC:DD:EE:FF"),
        "status": "INITIAL GATEWAY (TRUSTED)",
        "last_updated": time.strftime("%H:%M:%S")
    }
]

last_sender_data = {
    "status": "READY",
    "seq_id": "PKT-0000",
    "sender_ip": config.get("local_ip", "192.168.56.10"),
    "sender_mac": config.get("local_mac", "08:00:27:11:22:33"),
    "target_ip": config.get("peer_ip", "192.168.56.20"),
    "target_mac": config.get("peer_mac", "08:00:27:AA:BB:CC"),
    "hash_algo": "SHA-512",
    "timestamp": None,
    "nonce": None,
    "cipher_mode": "AES-256-GCM",
    "signature_preview": "None",
    "envelope_preview": "No packet generated yet.",
    "logs": []
}

last_attacker_data = {
    "status": "IDLE",
    "seq_id": "PKT-0000",
    "attack_type": "None",
    "claimed_ip": config.get("gateway_ip", "192.168.56.1"),
    "attacker_mac": config.get("attacker_mac", "11:22:33:44:55:66"),
    "target_ip": config.get("peer_ip", "192.168.56.20"),
    "key_used": "attacker_private.pem",
    "tampered_field": "None",
    "tampered_value": "None",
    "intended_effect": "No attack launched yet.",
    "defense_triggered": "None",
    "logs": []
}

last_receiver_data = {
    "status": "LISTENING",
    "seq_id": "PKT-0000",
    "decision": "WAITING",
    "reason": "Listening on loopback interface for incoming ARP frames...",
    "source_ip": "—",
    "source_mac": "—",
    "arp_status": "Cache in baseline state",
    "alert_triggered": False,
    "timestamp": None
}


# Input Validation Utilities
def validate_ipv4(ip_str):
    if not isinstance(ip_str, str):
        return False
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        num = int(p)
        if num < 0 or num > 255:
            return False
    return True


def validate_mac(mac_str):
    if not isinstance(mac_str, str):
        return False
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac_str.strip()))


def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    s = nonce_str.strip()
    if len(s) < 8 or len(s) > 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def validate_timestamp(ts_val):
    try:
        float(ts_val)
        return True
    except (ValueError, TypeError):
        return False


def add_log(message, category="info"):
    timestamp_str = time.strftime("[%H:%M:%S] ")
    logs_buffer.append({"timestamp": timestamp_str, "text": message, "category": category})
    if len(logs_buffer) > 250:
        logs_buffer.pop(0)


# Initialize logs
add_log("Authenticated ARP System Initialized.", "info")
add_log(f"Active Mode: {crypto_mode.upper()} | Interface: {config.get('interface', 'lo')}", "info")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/compute_hash", methods=["POST"])
def api_compute_hash():
    data = request.get_json(silent=True) or {}
    sender_ip = data.get("sender_ip", config.get("local_ip", "192.168.56.10"))
    sender_mac = data.get("sender_mac", config.get("local_mac", "08:00:27:11:22:33"))
    target_ip = data.get("target_ip", config.get("peer_ip", "192.168.56.20"))
    target_mac = data.get("target_mac", config.get("peer_mac", "08:00:27:AA:BB:CC"))
    timestamp = data.get("timestamp", round(time.time(), 3))
    nonce = data.get("nonce", "156adce85310615e373d8ea44a84341b")

    canonical_str = canonical_representation(sender_ip, sender_mac, target_ip, target_mac, timestamp, nonce)
    sha512_hex, _ = compute_sha512(canonical_str)
    md5_hex, _ = compute_md5(canonical_str)

    active_hash = sha512_hex if crypto_mode == "secure" else md5_hex
    active_algo = "SHA-512" if crypto_mode == "secure" else "MD5"

    return jsonify({
        "canonical_string": canonical_str,
        "active_algo": active_algo,
        "active_hash": active_hash,
        "sha512_hash": sha512_hex,
        "md5_hash": md5_hex,
        "timestamp": timestamp,
        "nonce": nonce
    })


@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "config": {
            "crypto_mode": crypto_mode,
            "local_ip": config.get("local_ip", "192.168.56.10"),
            "local_mac": config.get("local_mac", "08:00:27:11:22:33"),
            "peer_ip": config.get("peer_ip", "192.168.56.20"),
            "peer_mac": config.get("peer_mac", "08:00:27:AA:BB:CC"),
            "gateway_ip": config.get("gateway_ip", "192.168.56.1"),
            "gateway_mac": config.get("gateway_mac", "AA:BB:CC:DD:EE:FF"),
            "attacker_ip": config.get("attacker_ip", "192.168.56.30"),
            "attacker_mac": config.get("attacker_mac", "11:22:33:44:55:66"),
            "interface": config.get("interface", "lo")
        },
        "counters": counters,
        "pipeline": latest_pipeline,
        "logs": logs_buffer,
        "live_stream_active": live_stream_active,
        "live_stream_interval": live_stream_interval,
        "live_stream_mode": live_stream_mode,
        "seq_counter": seq_counter,
        "sender": last_sender_data,
        "attacker": last_attacker_data,
        "receiver": last_receiver_data,
        "arp_cache": arp_cache,
        "packet_history": packet_history[:15]
    })


def process_packet_verification(pkt, result, role_source="sender", custom_type="LEGITIMATE"):
    global last_valid_packet, last_receiver_data, arp_cache, seq_counter, packet_history
    status = result["status"]
    reason = result["reason"]
    details = result.get("details", {})
    msg = result.get("message") or {}

    seq_counter += 1
    seq_id = f"PKT-{seq_counter:04d}"

    # Update pipeline badges
    latest_pipeline["decryption"] = details.get("decryption", "FAIL")
    latest_pipeline["dss_signature"] = details.get("dss_signature", "FAIL")
    latest_pipeline["hash_integrity"] = details.get("hash_integrity", "FAIL")
    latest_pipeline["timestamp"] = details.get("timestamp", "FAIL")
    latest_pipeline["nonce"] = details.get("nonce", "FAIL")

    now_str = time.strftime("%H:%M:%S")

    sender_ip = msg.get("sender_ip", config.get("local_ip", "192.168.56.10"))
    sender_mac = msg.get("sender_mac", config.get("local_mac", "08:00:27:11:22:33"))
    target_ip = msg.get("target_ip", config.get("peer_ip", "192.168.56.20"))
    target_mac = msg.get("target_mac", config.get("peer_mac", "08:00:27:AA:BB:CC"))

    if status == "ACCEPT":
        last_valid_packet = pkt
        counters["valid"] += 1
        add_log(f"[PASS] {seq_id} ACCEPTED: Authenticated ARP response verified ({sender_ip} -> {sender_mac})", "pass")

        # Update ARP cache table
        existing = False
        for entry in arp_cache:
            if entry["ip"] == sender_ip:
                entry["mac"] = sender_mac
                entry["status"] = "AUTHENTICATED (DSS + SHA-512)"
                entry["last_updated"] = now_str
                existing = True
                break
        if not existing:
            arp_cache.append({
                "ip": sender_ip,
                "mac": sender_mac,
                "status": "AUTHENTICATED (DSS + SHA-512)",
                "last_updated": now_str
            })

        last_receiver_data = {
            "status": "PACKET ACCEPTED",
            "seq_id": seq_id,
            "decision": "ACCEPT",
            "reason": "All 5 cryptographic pipeline verification checks PASSED.",
            "source_ip": sender_ip,
            "source_mac": sender_mac,
            "details": latest_pipeline.copy(),
            "arp_status": f"Secure ARP Cache Updated: {sender_ip} -> {sender_mac}",
            "alert_triggered": False,
            "timestamp": now_str
        }
    else:
        counters["rejected"] += 1
        attack_category = "Generic Anomaly"
        if custom_type == "TAMPERING" or "integrity" in reason.lower() or "tamper" in reason.lower():
            counters["tampering"] += 1
            attack_category = "Packet Tampering"
        elif custom_type == "REPLAY" or "replay" in reason.lower() or details.get("nonce") == "FAIL":
            counters["replay"] += 1
            attack_category = "Replay Attack"
        elif custom_type == "SPOOFING" or "spoofing" in reason.lower() or details.get("dss_signature") == "FAIL":
            counters["spoofing"] += 1
            attack_category = "ARP Spoofing"
        elif details.get("hash_integrity") == "FAIL":
            counters["tampering"] += 1
            attack_category = "Packet Tampering"
        else:
            attack_category = "Generic Anomaly"

        add_log(f"[FAIL] {seq_id} REJECTED: {reason}", "fail")

        sender_ip_claimed = msg.get("sender_ip", "Claimed Gateway / Unknown")
        sender_mac_claimed = msg.get("sender_mac", "Attacker MAC / Unknown")

        last_receiver_data = {
            "status": "PACKET REJECTED",
            "seq_id": seq_id,
            "decision": "REJECT",
            "reason": reason,
            "source_ip": sender_ip_claimed,
            "source_mac": sender_mac_claimed,
            "attack_category": attack_category,
            "details": latest_pipeline.copy(),
            "arp_status": "ARP Cache PROTECTED! Malicious binding discarded without cache poisoning.",
            "alert_triggered": True,
            "timestamp": now_str
        }

    # Record in packet history
    packet_record = {
        "seq_id": seq_id,
        "timestamp_str": now_str,
        "type": custom_type,
        "sender_ip": sender_ip,
        "sender_mac": sender_mac,
        "target_ip": target_ip,
        "target_mac": target_mac,
        "decision": status,
        "reason": reason,
        "details": latest_pipeline.copy()
    }
    packet_history.insert(0, packet_record)
    if len(packet_history) > 50:
        packet_history.pop()

    return result


def execute_legitimate(custom_data=None):
    global last_sender_data
    config["crypto_mode"] = crypto_mode
    
    custom_message = None
    if custom_data:
        sender_ip = custom_data.get("sender_ip", config.get("local_ip", "192.168.56.10")).strip()
        sender_mac = custom_data.get("sender_mac", config.get("local_mac", "08:00:27:11:22:33")).strip()
        target_ip = custom_data.get("target_ip", config.get("peer_ip", "192.168.56.20")).strip()
        target_mac = custom_data.get("target_mac", config.get("peer_mac", "08:00:27:AA:BB:CC")).strip()
        nonce = custom_data.get("nonce")
        if nonce:
            nonce = nonce.strip()
        timestamp = custom_data.get("timestamp")
        if timestamp is not None:
            try:
                timestamp = float(timestamp)
            except ValueError:
                timestamp = None
        from arp.message import AuthenticatedARPMessage
        custom_message = AuthenticatedARPMessage(sender_ip, sender_mac, target_ip, target_mac, timestamp=timestamp, nonce=nonce)

    add_log(f"[INFO] [Sender/Gateway] Constructing and transmitting authenticated ARP ({crypto_mode.upper()})...", "info")
    pkt, logs = send_authenticated_arp(config, custom_message=custom_message, send_real_packet=False)

    try:
        from scapy.all import Raw
        payload = pkt[Raw].load if hasattr(pkt, "__contains__") and Raw in pkt else getattr(pkt, "load", b"")
    except Exception:
        payload = getattr(pkt, "load", b"")
    
    envelope_preview = ""
    try:
        parsed_env = json.loads(payload.decode("utf-8"))
        envelope_preview = json.dumps(parsed_env, indent=2)
    except Exception:
        envelope_preview = str(payload)[:200]

    result = verify_received_payload(payload, config, replay_protector=replay_protector)
    msg = result.get("message") or {}

    res_seq = f"PKT-{seq_counter + 1:04d}"

    last_sender_data = {
        "status": "PACKET TRANSMITTED",
        "seq_id": res_seq,
        "sender_ip": msg.get("sender_ip", config.get("local_ip", "192.168.56.10")),
        "sender_mac": msg.get("sender_mac", config.get("local_mac", "08:00:27:11:22:33")),
        "target_ip": msg.get("target_ip", config.get("peer_ip", "192.168.56.20")),
        "target_mac": msg.get("target_mac", config.get("peer_mac", "08:00:27:AA:BB:CC")),
        "hash_algo": "SHA-512" if crypto_mode == "secure" else "MD5",
        "timestamp": msg.get("timestamp"),
        "nonce": msg.get("nonce"),
        "cipher_mode": "AES-256-GCM" if crypto_mode == "secure" else "DES-CBC",
        "envelope_preview": envelope_preview,
        "logs": logs
    }

    return process_packet_verification(pkt, result, role_source="sender", custom_type="LEGITIMATE")


def execute_spoofing(custom_data=None):
    global last_attacker_data
    config["crypto_mode"] = crypto_mode
    cfg_copy = config.copy()
    if custom_data:
        if "gateway_ip" in custom_data and custom_data["gateway_ip"]:
            cfg_copy["gateway_ip"] = custom_data["gateway_ip"].strip()
        if "attacker_mac" in custom_data and custom_data["attacker_mac"]:
            cfg_copy["attacker_mac"] = custom_data["attacker_mac"].strip()
        if "target_ip" in custom_data and custom_data["target_ip"]:
            cfg_copy["peer_ip"] = custom_data["target_ip"].strip()

    add_log(f"[WARN] [Attacker/Kali] Injecting forged ARP spoofing frame (Claiming {cfg_copy['gateway_ip']} -> {cfg_copy['attacker_mac']})...", "warn")
    pkt, logs = simulate_arp_spoofing(cfg_copy)
    try:
        from scapy.all import Raw
        payload = pkt[Raw].load if hasattr(pkt, "__contains__") and Raw in pkt else getattr(pkt, "load", b"")
    except Exception:
        payload = getattr(pkt, "load", b"")
    result = verify_received_payload(payload, config, replay_protector=replay_protector)

    res_seq = f"PKT-{seq_counter + 1:04d}"

    last_attacker_data = {
        "status": "ATTACK INJECTED",
        "seq_id": res_seq,
        "attack_type": "ARP Spoofing (Unauthorized Gateway Claim)",
        "claimed_ip": cfg_copy.get("gateway_ip", "192.168.56.1"),
        "attacker_mac": cfg_copy.get("attacker_mac", "11:22:33:44:55:66"),
        "target_ip": cfg_copy.get("peer_ip", "192.168.56.20"),
        "key_used": "attacker_private.pem (unauthorized signature)",
        "tampered_field": "None (Forged Binding)",
        "tampered_value": f"{cfg_copy.get('gateway_ip')} -> {cfg_copy.get('attacker_mac')}",
        "intended_effect": "Poison victim ARP table to divert gateway traffic to attacker MAC",
        "defense_triggered": "DSS Digital Signature Verification FAILED (Sender key mismatch)",
        "logs": logs
    }

    return process_packet_verification(pkt, result, role_source="attacker", custom_type="SPOOFING")


def execute_replay():
    global last_attacker_data
    config["crypto_mode"] = crypto_mode
    add_log("[WARN] [Attacker/Kali] Injecting replay attack frame (Duplicate cached packet)...", "warn")
    pkt, logs = simulate_replay_attack(config, original_pkt=last_valid_packet)
    try:
        from scapy.all import Raw
        payload = pkt[Raw].load if hasattr(pkt, "__contains__") and Raw in pkt else getattr(pkt, "load", b"")
    except Exception:
        payload = getattr(pkt, "load", b"")
    result = verify_received_payload(payload, config, replay_protector=replay_protector)

    res_seq = f"PKT-{seq_counter + 1:04d}"

    last_attacker_data = {
        "status": "ATTACK INJECTED",
        "seq_id": res_seq,
        "attack_type": "Replay Attack (Duplicate Stale Packet)",
        "claimed_ip": "Cached Gateway / Victim IP",
        "attacker_mac": "Pre-captured Valid MAC",
        "target_ip": config.get("peer_ip", "192.168.56.20"),
        "key_used": "Pre-signed Intercepted Frame",
        "tampered_field": "nonce (Reused)",
        "tampered_value": "Duplicate Intercepted Token",
        "intended_effect": "Reuse valid credentials outside original transmission window",
        "defense_triggered": "Replay Protection FAILED (Duplicate Nonce already used)",
        "logs": logs
    }

    return process_packet_verification(pkt, result, role_source="attacker", custom_type="REPLAY")


def execute_tampering(custom_data=None):
    global last_attacker_data
    config["crypto_mode"] = crypto_mode
    field_to_tamper = "sender_mac"
    custom_val = "11:22:33:44:55:66"
    if custom_data:
        field_to_tamper = custom_data.get("field_to_tamper", "sender_mac").strip()
        custom_val = custom_data.get("custom_value", "11:22:33:44:55:66").strip()

    add_log(f"[WARN] [Attacker/Kali] Injecting packet tampering frame (Modified {field_to_tamper} to '{custom_val}')...", "warn")
    pkt, logs = simulate_tampering_attack(config, field_to_tamper=field_to_tamper, custom_value=custom_val)
    try:
        from scapy.all import Raw
        payload = pkt[Raw].load if hasattr(pkt, "__contains__") and Raw in pkt else getattr(pkt, "load", b"")
    except Exception:
        payload = getattr(pkt, "load", b"")
    result = verify_received_payload(payload, config, replay_protector=replay_protector)

    res_seq = f"PKT-{seq_counter + 1:04d}"

    last_attacker_data = {
        "status": "ATTACK INJECTED",
        "seq_id": res_seq,
        "attack_type": "Packet Tampering (Field Alteration)",
        "claimed_ip": config.get("local_ip", "192.168.56.10"),
        "attacker_mac": custom_val if field_to_tamper == "sender_mac" else config.get("local_mac"),
        "target_ip": config.get("peer_ip", "192.168.56.20"),
        "tampered_field": field_to_tamper,
        "tampered_value": custom_val,
        "key_used": "Original DSS Signature (Now Inconsistent with Payload)",
        "intended_effect": "Alter binding in transit while keeping old digital signature",
        "defense_triggered": "SHA-512 Hash Mismatch / DSS Verification FAILED",
        "logs": logs
    }

    return process_packet_verification(pkt, result, role_source="attacker", custom_type="TAMPERING")


@app.route("/api/send_legitimate", methods=["POST"])
def api_send_legitimate():
    data = request.get_json(silent=True) or {}
    
    # Input validation
    if "sender_ip" in data and not validate_ipv4(data["sender_ip"]):
        return jsonify({"error": f"Invalid IPv4 format for Sender IP: '{data['sender_ip']}'"}), 400
    if "target_ip" in data and not validate_ipv4(data["target_ip"]):
        return jsonify({"error": f"Invalid IPv4 format for Target IP: '{data['target_ip']}'"}), 400
    if "sender_mac" in data and not validate_mac(data["sender_mac"]):
        return jsonify({"error": f"Invalid MAC address format for Sender MAC: '{data['sender_mac']}' (Expected XX:XX:XX:XX:XX:XX)"}), 400
    if "target_mac" in data and not validate_mac(data["target_mac"]):
        return jsonify({"error": f"Invalid MAC address format for Target MAC: '{data['target_mac']}' (Expected XX:XX:XX:XX:XX:XX)"}), 400
    if "nonce" in data and not validate_nonce(data["nonce"]):
        return jsonify({"error": f"Invalid Nonce token: '{data['nonce']}' (Must be hexadecimal string)"}), 400
    if "timestamp" in data and data["timestamp"] is not None and not validate_timestamp(data["timestamp"]):
        return jsonify({"error": "Invalid Timestamp: must be numeric unix epoch seconds"}), 400

    res = execute_legitimate(custom_data=data)
    return jsonify({
        "result": res,
        "sender": last_sender_data,
        "receiver": last_receiver_data,
        "arp_cache": arp_cache,
        "packet_history": packet_history[:15]
    })


@app.route("/api/simulate_spoofing", methods=["POST"])
def api_simulate_spoofing():
    data = request.get_json(silent=True) or {}
    if "gateway_ip" in data and not validate_ipv4(data["gateway_ip"]):
        return jsonify({"error": f"Invalid Gateway IPv4 format: '{data['gateway_ip']}'"}), 400
    if "attacker_mac" in data and not validate_mac(data["attacker_mac"]):
        return jsonify({"error": f"Invalid Attacker MAC address format: '{data['attacker_mac']}'"}), 400
    if "target_ip" in data and not validate_ipv4(data["target_ip"]):
        return jsonify({"error": f"Invalid Target IPv4 format: '{data['target_ip']}'"}), 400

    res = execute_spoofing(custom_data=data)
    return jsonify({
        "result": res,
        "attacker": last_attacker_data,
        "receiver": last_receiver_data,
        "arp_cache": arp_cache,
        "packet_history": packet_history[:15]
    })


@app.route("/api/simulate_replay", methods=["POST"])
def api_simulate_replay():
    res = execute_replay()
    return jsonify({
        "result": res,
        "attacker": last_attacker_data,
        "receiver": last_receiver_data,
        "arp_cache": arp_cache,
        "packet_history": packet_history[:15]
    })


@app.route("/api/simulate_tampering", methods=["POST"])
def api_simulate_tampering():
    data = request.get_json(silent=True) or {}
    field = data.get("field_to_tamper", "sender_mac")
    val = data.get("custom_value", "11:22:33:44:55:66")
    
    if field == "sender_mac" and not validate_mac(val):
        return jsonify({"error": f"Invalid MAC format for tampered sender_mac: '{val}'"}), 400
    if field == "sender_ip" and not validate_ipv4(val):
        return jsonify({"error": f"Invalid IP format for tampered sender_ip: '{val}'"}), 400

    res = execute_tampering(custom_data=data)
    return jsonify({
        "result": res,
        "attacker": last_attacker_data,
        "receiver": last_receiver_data,
        "arp_cache": arp_cache,
        "packet_history": packet_history[:15]
    })


@app.route("/api/reset_arp_cache", methods=["POST"])
def api_reset_arp_cache():
    global arp_cache
    arp_cache = [
        {
            "ip": config.get("gateway_ip", "192.168.56.1"),
            "mac": config.get("gateway_mac", "AA:BB:CC:DD:EE:FF"),
            "status": "INITIAL GATEWAY (TRUSTED)",
            "last_updated": time.strftime("%H:%M:%S")
        }
    ]
    add_log("[INFO] Receiver ARP cache table reset to initial baseline state.", "info")
    return jsonify({"status": "reset", "arp_cache": arp_cache})


@app.route("/api/reset_simulation", methods=["POST"])
def api_reset_simulation():
    global live_stream_active, counters, seq_counter, packet_history, arp_cache
    global last_sender_data, last_attacker_data, last_receiver_data, latest_pipeline

    # 1. Stop stream
    live_stream_active = False

    # 2. Reset counters
    counters = {
        "valid": 0,
        "rejected": 0,
        "spoofing": 0,
        "replay": 0,
        "tampering": 0
    }

    # 3. Clear Replay Nonce Cache
    replay_protector.clear()

    # 4. Reset sequences and packet history
    seq_counter = 0
    packet_history = []

    # 5. Reset Pipeline Badges
    latest_pipeline = {
        "decryption": "WAITING",
        "dss_signature": "WAITING",
        "hash_integrity": "WAITING",
        "timestamp": "WAITING",
        "nonce": "WAITING"
    }

    # 6. Reset ARP Cache table
    arp_cache = [
        {
            "ip": config.get("gateway_ip", "192.168.56.1"),
            "mac": config.get("gateway_mac", "AA:BB:CC:DD:EE:FF"),
            "status": "INITIAL GATEWAY (TRUSTED)",
            "last_updated": time.strftime("%H:%M:%S")
        }
    ]

    # 7. Reset last states
    last_sender_data = {
        "status": "READY",
        "seq_id": "PKT-0000",
        "sender_ip": config.get("local_ip", "192.168.56.10"),
        "sender_mac": config.get("local_mac", "08:00:27:11:22:33"),
        "target_ip": config.get("peer_ip", "192.168.56.20"),
        "target_mac": config.get("peer_mac", "08:00:27:AA:BB:CC"),
        "hash_algo": "SHA-512" if crypto_mode == "secure" else "MD5",
        "timestamp": None,
        "nonce": None,
        "cipher_mode": "AES-256-GCM" if crypto_mode == "secure" else "DES-CBC",
        "signature_preview": "None",
        "envelope_preview": "Simulation reset to baseline state.",
        "logs": []
    }

    last_attacker_data = {
        "status": "IDLE",
        "seq_id": "PKT-0000",
        "attack_type": "None",
        "claimed_ip": config.get("gateway_ip", "192.168.56.1"),
        "attacker_mac": config.get("attacker_mac", "11:22:33:44:55:66"),
        "target_ip": config.get("peer_ip", "192.168.56.20"),
        "key_used": "attacker_private.pem",
        "tampered_field": "None",
        "tampered_value": "None",
        "intended_effect": "No attack launched yet.",
        "defense_triggered": "None",
        "logs": []
    }

    last_receiver_data = {
        "status": "LISTENING",
        "seq_id": "PKT-0000",
        "decision": "WAITING",
        "reason": "Listening on loopback interface for incoming ARP frames...",
        "source_ip": "—",
        "source_mac": "—",
        "arp_status": "Cache in baseline state",
        "alert_triggered": False,
        "timestamp": None
    }

    add_log("[INFO] Complete simulation state reset to baseline.", "info")

    return jsonify({
        "status": "reset",
        "counters": counters,
        "arp_cache": arp_cache,
        "pipeline": latest_pipeline,
        "seq_counter": seq_counter
    })


# Live Dynamic Traffic Worker Loop
def live_traffic_worker():
    global live_stream_active
    while live_stream_active:
        time.sleep(live_stream_interval)
        if not live_stream_active:
            break

        mode = live_stream_mode.lower()
        if mode == "legitimate":
            execute_legitimate()
        elif mode == "spoofing":
            execute_spoofing()
        elif mode == "tampering":
            execute_tampering()
        elif mode == "replay":
            execute_replay()
        elif mode == "mixed":
            r = random.random()
            if r < 0.70:
                execute_legitimate()
            elif r < 0.85:
                execute_spoofing()
            elif r < 0.95:
                execute_replay()
            else:
                execute_tampering()


@app.route("/api/start_stream", methods=["POST"])
def api_start_stream():
    global live_stream_active, stream_thread, live_stream_mode, live_stream_interval
    data = request.get_json(silent=True) or {}
    
    if "mode" in data and data["mode"]:
        live_stream_mode = str(data["mode"]).lower()
    if "interval" in data:
        try:
            val = float(data["interval"])
            if 0.2 <= val <= 30.0:
                live_stream_interval = val
        except ValueError:
            pass

    if not live_stream_active:
        live_stream_active = True
        add_log(f"[INFO] Dynamic traffic stream started (Mode: {live_stream_mode.upper()}, Interval: {live_stream_interval}s).", "pass")
        stream_thread = threading.Thread(target=live_traffic_worker, daemon=True)
        stream_thread.start()

    return jsonify({
        "live_stream_active": True,
        "live_stream_mode": live_stream_mode,
        "live_stream_interval": live_stream_interval
    })


@app.route("/api/stop_stream", methods=["POST"])
def api_stop_stream():
    global live_stream_active
    if live_stream_active:
        live_stream_active = False
        add_log("[INFO] Dynamic traffic stream paused.", "warn")
    return jsonify({"live_stream_active": False})


@app.route("/api/toggle_mode", methods=["POST"])
def api_toggle_mode():
    global crypto_mode
    if crypto_mode == "secure":
        crypto_mode = "legacy"
        add_log("[WARN] Cryptographic mode changed to LEGACY (MD5 + DSS + DES-CBC).", "warn")
    else:
        crypto_mode = "secure"
        add_log("[PASS] Cryptographic mode changed to SECURE (SHA-512 + DSS + AES-256-GCM).", "pass")

    config["crypto_mode"] = crypto_mode
    return jsonify({"crypto_mode": crypto_mode})


@app.route("/api/clear_logs", methods=["POST"])
def api_clear_logs():
    global logs_buffer
    logs_buffer = []
    return jsonify({"status": "cleared"})


# ─────────────────────────────────────────────────────────────────────────────
# AWS S3 ROUTES — Component 3 (Bucket Management) & Component 4 (Secure Upload)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/aws/buckets", methods=["GET"])
def aws_list_buckets():
    from aws.s3_manager import list_buckets
    buckets, msg = list_buckets()
    return jsonify({"buckets": buckets, "message": msg})


@app.route("/api/aws/buckets", methods=["POST"])
def aws_create_bucket():
    data = request.get_json(silent=True) or {}
    bucket_name = data.get("bucket_name", "").strip()
    region = data.get("region", "us-east-1").strip()
    if not bucket_name:
        return jsonify({"error": "bucket_name is required"}), 400
    from aws.s3_manager import create_bucket
    success, msg = create_bucket(bucket_name, region)
    return jsonify({"success": success, "message": msg}), (200 if success else 400)


@app.route("/api/aws/buckets/<bucket_name>", methods=["DELETE"])
def aws_delete_bucket(bucket_name):
    from aws.s3_manager import delete_bucket
    success, msg = delete_bucket(bucket_name)
    return jsonify({"success": success, "message": msg}), (200 if success else 400)


@app.route("/api/aws/buckets/<bucket_name>/objects", methods=["GET"])
def aws_list_objects(bucket_name):
    from aws.s3_manager import list_objects
    objects, msg = list_objects(bucket_name)
    return jsonify({"objects": objects, "message": msg})


@app.route("/api/aws/buckets/<bucket_name>/objects/<path:key>", methods=["DELETE"])
def aws_delete_object(bucket_name, key):
    from aws.s3_manager import delete_object
    success, msg = delete_object(bucket_name, key)
    return jsonify({"success": success, "message": msg}), (200 if success else 400)


@app.route("/api/aws/secure-upload", methods=["POST"])
def aws_secure_upload():
    """Component 4: Encrypt file with AES-256-GCM + SHA-256 integrity, upload to S3."""
    bucket_name = request.form.get("bucket_name", "").strip()
    password = request.form.get("password", "").strip()
    region = request.form.get("region", "us-east-1").strip()

    if not bucket_name or not password:
        return jsonify({"error": "bucket_name and password are required"}), 400
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    file_bytes = f.read()
    from aws.secure_upload import secure_upload
    success, msg, meta = secure_upload(bucket_name, file_bytes, f.filename, password, region)
    return jsonify({"success": success, "message": msg, "metadata": meta}), (200 if success else 400)


@app.route("/api/aws/secure-files", methods=["GET"])
def aws_list_secure_files():
    bucket_name = request.args.get("bucket", "").strip()
    region = request.args.get("region", "us-east-1").strip()
    if not bucket_name:
        return jsonify({"error": "bucket query param required"}), 400
    from aws.secure_upload import list_secure_files
    files, msg = list_secure_files(bucket_name, region)
    return jsonify({"files": files, "message": msg})


@app.route("/api/aws/secure-download", methods=["POST"])
def aws_secure_download():
    """Component 4: Download, verify SHA-256 integrity, and decrypt file from S3."""
    data = request.get_json(silent=True) or {}
    bucket_name = data.get("bucket_name", "").strip()
    s3_key = data.get("s3_key", "").strip()
    password = data.get("password", "").strip()
    region = data.get("region", "us-east-1").strip()

    if not bucket_name or not s3_key or not password:
        return jsonify({"error": "bucket_name, s3_key, and password are required"}), 400

    from aws.secure_upload import secure_download
    success, msg, file_bytes, meta = secure_download(bucket_name, s3_key, password, region)
    if not success:
        return jsonify({"success": False, "message": msg, "metadata": meta}), 400

    import base64
    return jsonify({
        "success": True,
        "message": msg,
        "metadata": meta,
        "file_b64": base64.b64encode(file_bytes).decode()
    })


def launch_web_ui(port=None):
    import os
    port = port or int(os.environ.get("PORT", 8000))
    generate_all_keys(config.get("keys_dir", "keys"))
    is_local = os.environ.get("FLASK_ENV") != "production"
    host = "127.0.0.1" if is_local else "0.0.0.0"
    url = f"http://localhost:{port}"
    print(f"\n[✓] Web UI Dashboard active at: {url}\n")

    if is_local:
        def open_browser():
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Timer(1.0, open_browser).start()

    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    launch_web_ui()
