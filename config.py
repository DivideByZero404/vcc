"""
Configuration module for Cryptographically Authenticated ARP.
Loads settings from config.yaml and provides command-line argument parsing.
"""

import os
import argparse

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DEFAULT_CONFIG = {
    "mode": "sender",
    "crypto_mode": "secure",
    "local_ip": "192.168.56.10",
    "local_mac": "08:00:27:11:22:33",
    "peer_ip": "192.168.56.20",
    "peer_mac": "08:00:27:AA:BB:CC",
    "gateway_ip": "192.168.56.1",
    "gateway_mac": "AA:BB:CC:DD:EE:FF",
    "attacker_ip": "192.168.56.30",
    "attacker_mac": "11:22:33:44:55:66",
    "interface": "lo",
    "timestamp_max_drift": 60,
    "keys_dir": "keys"
}


def load_config(config_path="config.yaml"):
    """Load configuration from a YAML file, falling back to defaults if missing or PyYAML unavailable."""
    config = DEFAULT_CONFIG.copy()
    if HAS_YAML and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                file_cfg = yaml.safe_load(f)
                if file_cfg and isinstance(file_cfg, dict):
                    config.update(file_cfg)
        except Exception as e:
            print(f"[!] Warning: Failed to load {config_path} ({e}). Using default configuration.")
    return config


def parse_args(config_dict=None):
    """Parse CLI arguments and override configuration parameters."""
    if config_dict is None:
        config_dict = load_config()

    parser = argparse.ArgumentParser(
        description="Cryptographically Authenticated ARP Agent for ARP Spoofing Prevention"
    )
    parser.add_argument(
        "--mode",
        choices=["sender", "receiver", "attack", "gui", "ui", "web"],
        default=config_dict.get("mode", "ui"),
        help="Operating mode: sender, receiver, attack, gui (desktop), or ui / web (browser)"
    )
    parser.add_argument(
        "--crypto-mode",
        choices=["secure", "legacy"],
        default=config_dict.get("crypto_mode", "secure"),
        help="Security mode: secure (SHA-512/DSS/AES-GCM) or legacy (MD5/DSS/DES-CBC)"
    )
    parser.add_argument(
        "--local-ip",
        default=config_dict.get("local_ip"),
        help="Local IP address"
    )
    parser.add_argument(
        "--local-mac",
        default=config_dict.get("local_mac"),
        help="Local MAC address"
    )
    parser.add_argument(
        "--peer-ip",
        default=config_dict.get("peer_ip"),
        help="Peer IP address"
    )
    parser.add_argument(
        "--peer-mac",
        default=config_dict.get("peer_mac"),
        help="Peer MAC address"
    )
    parser.add_argument(
        "--interface",
        default=config_dict.get("interface", "lo"),
        help="Network interface to use (e.g., eth0, lo, vboxnet0)"
    )
    parser.add_argument(
        "--attack-type",
        choices=["spoofing", "replay", "tampering"],
        default="spoofing",
        help="Attack simulation type when --mode attack"
    )

    args = parser.parse_args()

    config_dict["mode"] = args.mode
    config_dict["crypto_mode"] = args.crypto_mode
    config_dict["local_ip"] = args.local_ip
    config_dict["local_mac"] = args.local_mac
    config_dict["peer_ip"] = args.peer_ip
    config_dict["peer_mac"] = args.peer_mac
    config_dict["interface"] = args.interface
    config_dict["attack_type"] = args.attack_type

    return config_dict
