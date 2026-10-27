#!/usr/bin/env python3
"""
Main Entry Point for Cryptographically Authenticated ARP.
Supports SENDER, RECEIVER, ATTACK simulation, and GUI modes.
"""

import sys
import logging
from config import parse_args
from keys.generate_keys import generate_all_keys
from arp.sender import send_authenticated_arp
from arp.receiver import receive_authenticated_arp
from attacks.spoofing import simulate_arp_spoofing
from attacks.replay import simulate_replay_attack
from attacks.tampering import simulate_tampering_attack
from gui.dashboard import launch_gui

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("SecureARP.Main")


def main():
    config = parse_args()
    mode = config.get("mode", "gui").lower()
    crypto_mode = config.get("crypto_mode", "secure").lower()
    keys_dir = config.get("keys_dir", "keys")

    # Ensure cryptographic key material is initialized
    generate_all_keys(keys_dir)

    print("\n=======================================================")
    print("   CRYPTOGRAPHICALLY AUTHENTICATED ARP AGENT")
    print("=======================================================")
    print(f"[*] Operating Mode : {mode.upper()}")
    print(f"[*] Security Mode  : {crypto_mode.upper()}")
    print(f"[*] Local Node IP  : {config.get('local_ip')} ({config.get('local_mac')})")
    print(f"[*] Interface      : {config.get('interface')}")
    print("=======================================================\n")

    if mode == "sender":
        logger.info("Starting Secure ARP Sender...")
        pkt, logs = send_authenticated_arp(config)
        for log_entry in logs:
            print(f"  {log_entry}")
        print("\n[✓] Sender workflow completed successfully.\n")

    elif mode == "receiver":
        logger.info("Starting Secure ARP Receiver (Sniffing for ARP packets)...")
        def on_packet_processed(pkt, result):
            print(f"\n[+] Packet Received!")
            print(f"    Status: {result['status']}")
            print(f"    Reason: {result['reason']}")
            print(f"    Details: {result['details']}\n")

        receive_authenticated_arp(config, packet_count=0, result_callback=on_packet_processed)

    elif mode == "attack":
        attack_type = config.get("attack_type", "spoofing").lower()
        logger.info(f"Starting Attack Simulation: '{attack_type.upper()}'...")

        if attack_type == "spoofing":
            pkt, logs = simulate_arp_spoofing(config)
        elif attack_type == "replay":
            pkt, logs = simulate_replay_attack(config)
        elif attack_type == "tampering":
            pkt, logs = simulate_tampering_attack(config)
        else:
            print(f"[!] Unknown attack type '{attack_type}'")
            sys.exit(1)

        for log_entry in logs:
            print(f"  {log_entry}")
        print("\n[✓] Attack simulation packet dispatched.\n")

    elif mode in ["ui", "web"]:
        logger.info("Launching Web UI Dashboard at http://127.0.0.1:5000...")
        from web_ui import launch_web_ui
        launch_web_ui()

    elif mode == "gui":
        logger.info("Launching Tkinter Graphical Security Dashboard...")
        launch_gui(config)

    else:
        print(f"[!] Invalid mode '{mode}'. Choose from: sender, receiver, attack, ui, gui.")
        sys.exit(1)


if __name__ == "__main__":
    main()
