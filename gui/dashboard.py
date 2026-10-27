"""
Tkinter Graphical User Interface for Cryptographically Authenticated ARP.
Displays live cryptographic verification badges, security logs, security alerts,
interactive controls, and real-time attack counters.
"""

import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from arp.sender import send_authenticated_arp
from arp.receiver import verify_received_payload
from arp.replay_protection import ReplayProtector
from attacks.spoofing import simulate_arp_spoofing
from attacks.replay import simulate_replay_attack
from attacks.tampering import simulate_tampering_attack
from config import load_config


class ARPDashboardApp:
    def __init__(self, root, config=None):
        self.root = root
        self.root.title("Cryptographically Authenticated ARP - Security Dashboard")
        self.root.geometry("980x720")
        self.root.minsize(850, 600)

        self.config = config if config else load_config()
        self.crypto_mode = self.config.get("crypto_mode", "secure").lower()
        self.replay_protector = ReplayProtector(max_drift_seconds=self.config.get("timestamp_max_drift", 60))

        # Counters
        self.count_valid = 0
        self.count_rejected = 0
        self.count_spoofing = 0
        self.count_replay = 0
        self.count_tampering = 0

        self.is_receiver_running = False
        self.last_valid_packet = None

        self._configure_styles()
        self._build_ui()
        self.log_info("[+] Cryptographically Authenticated ARP System Initialized.")
        self.log_info(f"[+] Active Mode: {self.crypto_mode.upper()} | Interface: {self.config.get('interface', 'lo')}")

    def _configure_styles(self):
        """Setup dark-mode color scheme and fonts."""
        self.bg_dark = "#1E1E2E"
        self.bg_card = "#252637"
        self.fg_text = "#CDD6F4"
        self.accent_blue = "#89B4FA"
        self.color_pass = "#A6E3A1"
        self.color_fail = "#F38BA8"
        self.color_warn = "#FAB387"

        self.root.configure(bg=self.bg_dark)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", background=self.bg_dark, foreground=self.fg_text, font=("Helvetica", 10))
        self.style.configure("TFrame", background=self.bg_dark)
        self.style.configure("Card.TFrame", background=self.bg_card, relief="flat", borderwidth=1)
        self.style.configure("Header.TLabel", font=("Helvetica", 16, "bold"), foreground=self.accent_blue, background=self.bg_dark)
        self.style.configure("SubHeader.TLabel", font=("Helvetica", 11, "bold"), foreground=self.fg_text, background=self.bg_card)
        self.style.configure("StatusPass.TLabel", font=("Helvetica", 10, "bold"), foreground=self.color_pass, background=self.bg_card)
        self.style.configure("StatusFail.TLabel", font=("Helvetica", 10, "bold"), foreground=self.color_fail, background=self.bg_card)
        self.style.configure("StatusWait.TLabel", font=("Helvetica", 10), foreground="#A6ADC8", background=self.bg_card)

    def _build_ui(self):
        """Construct dashboard frames and widgets."""
        # Header Bar
        header_frame = ttk.Frame(self.root, padding="15 15 15 5")
        header_frame.pack(fill="x")

        ttk.Label(header_frame, text="==========================================", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="   CRYPTOGRAPHICALLY AUTHENTICATED ARP", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="==========================================", style="Header.TLabel").pack(anchor="w")

        # Top Control & Info Bar
        top_bar = ttk.Frame(self.root, padding="15 5 15 10")
        top_bar.pack(fill="x")

        info_str = f"Local IP: {self.config.get('local_ip')} | Local MAC: {self.config.get('local_mac')} | Peer IP: {self.config.get('peer_ip')}"
        ttk.Label(top_bar, text=info_str, font=("Courier", 10, "bold"), foreground=self.accent_blue).pack(side="left")

        # Mode Selection Switch
        mode_frame = ttk.Frame(top_bar)
        mode_frame.pack(side="right")

        ttk.Label(mode_frame, text="Crypto Mode: ", font=("Helvetica", 10, "bold")).pack(side="left", padx=5)
        self.mode_var = tk.StringVar(value=self.crypto_mode.upper())
        self.mode_btn = tk.Button(
            mode_frame,
            textvariable=self.mode_var,
            command=self._toggle_mode,
            bg="#313244",
            fg=self.accent_blue,
            font=("Helvetica", 10, "bold"),
            padx=10,
            pady=2,
            relief="raised"
        )
        self.mode_btn.pack(side="left")

        # Main Workspace Container (2 Columns)
        main_container = ttk.Frame(self.root, padding="15 5 15 5")
        main_container.pack(fill="both", expand=True)

        # Left Column: Security Status Badges & Counters
        left_col = ttk.Frame(main_container, width=320)
        left_col.pack(side="left", fill="y", padx=(0, 10))

        # Status Badge Card
        status_card = ttk.Frame(left_col, style="Card.TFrame", padding="12")
        status_card.pack(fill="x", pady=(0, 10))

        ttk.Label(status_card, text="ARP AUTHENTICATION PIPELINE", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        self.hash_label_name = tk.StringVar(value="SHA-512")
        self.badge_hash = self._create_badge(status_card, self.hash_label_name, "WAITING")
        self.badge_dss = self._create_badge(status_card, "DSS Signature", "WAITING")
        self.cipher_label_name = tk.StringVar(value="AES-256-GCM")
        self.badge_cipher = self._create_badge(status_card, self.cipher_label_name, "WAITING")
        self.badge_ts = self._create_badge(status_card, "Timestamp Window", "WAITING")
        self.badge_nonce = self._create_badge(status_card, "Nonce Replay Check", "WAITING")

        # Counter Card
        counter_card = ttk.Frame(left_col, style="Card.TFrame", padding="12")
        counter_card.pack(fill="x")

        ttk.Label(counter_card, text="SECURITY METRICS & COUNTERS", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        self.lbl_valid = self._create_counter(counter_card, "Valid Packets Accepted:", "0", self.color_pass)
        self.lbl_rejected = self._create_counter(counter_card, "Total Packets Rejected:", "0", self.color_fail)
        self.lbl_spoof = self._create_counter(counter_card, "Spoofing Attacks Detected:", "0", self.color_warn)
        self.lbl_replay = self._create_counter(counter_card, "Replay Attacks Detected:", "0", self.color_warn)
        self.lbl_tamper = self._create_counter(counter_card, "Tampering Attacks Detected:", "0", self.color_warn)

        # Right Column: Live Security Logs
        right_col = ttk.Frame(main_container)
        right_col.pack(side="right", fill="both", expand=True)

        log_card = ttk.Frame(right_col, style="Card.TFrame", padding="10")
        log_card.pack(fill="both", expand=True)

        ttk.Label(log_card, text="REAL-TIME SECURITY LOG & AUDIT FEED", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 5))

        self.log_text = scrolledtext.ScrolledText(
            log_card,
            bg="#11111B",
            fg="#CDD6F4",
            insertbackground="white",
            font=("Courier", 9),
            wrap="word",
            relief="flat"
        )
        self.log_text.pack(fill="both", expand=True)

        # Tag configuration for colored text logging
        self.log_text.tag_config("PASS", foreground=self.color_pass)
        self.log_text.tag_config("FAIL", foreground=self.color_fail)
        self.log_text.tag_config("WARN", foreground=self.color_warn)
        self.log_text.tag_config("INFO", foreground=self.accent_blue)

        # Bottom Button Bar
        btn_frame = ttk.Frame(self.root, padding="15 10 15 15")
        btn_frame.pack(fill="x")

        btn_style = {"bg": "#313244", "fg": "white", "font": ("Helvetica", 9, "bold"), "padx": 8, "pady": 4, "relief": "raised"}

        self.btn_recv = tk.Button(btn_frame, text="Start Receiver", command=self._toggle_receiver, **btn_style)
        self.btn_recv.pack(side="left", padx=3)

        tk.Button(btn_frame, text="Send Legitimate ARP", command=self._send_legitimate, **btn_style).pack(side="left", padx=3)
        tk.Button(btn_frame, text="Simulate Spoofing", command=self._sim_spoofing, **btn_style).pack(side="left", padx=3)
        tk.Button(btn_frame, text="Simulate Replay Attack", command=self._sim_replay, **btn_style).pack(side="left", padx=3)
        tk.Button(btn_frame, text="Simulate Tampering", command=self._sim_tampering, **btn_style).pack(side="left", padx=3)
        tk.Button(btn_frame, text="Clear Logs", command=self._clear_logs, **btn_style).pack(side="right", padx=3)

    def _create_badge(self, parent, name, default_val):
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        if isinstance(name, tk.StringVar):
            lbl_name = ttk.Label(row, textvariable=name, font=("Helvetica", 9, "bold"), background=self.bg_card)
        else:
            lbl_name = ttk.Label(row, text=name, font=("Helvetica", 9, "bold"), background=self.bg_card)
        lbl_name.pack(side="left")

        val_var = tk.StringVar(value=default_val)
        val_lbl = ttk.Label(row, textvariable=val_var, style="StatusWait.TLabel")
        val_lbl.pack(side="right")
        return val_var, val_lbl

    def _create_counter(self, parent, label_text, default_val, color):
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label_text, font=("Helvetica", 9), background=self.bg_card).pack(side="left")

        cnt_var = tk.StringVar(value=default_val)
        cnt_lbl = ttk.Label(row, textvariable=cnt_var, font=("Helvetica", 10, "bold"), foreground=color, background=self.bg_card)
        cnt_lbl.pack(side="right")
        return cnt_var

    def _update_badge(self, badge_tuple, status_text):
        val_var, val_lbl = badge_tuple
        val_var.set(status_text)
        if status_text == "✓ PASS":
            val_lbl.configure(style="StatusPass.TLabel")
        elif "FAIL" in status_text:
            val_lbl.configure(style="StatusFail.TLabel")
        else:
            val_lbl.configure(style="StatusWait.TLabel")

    def log_info(self, text, tag="INFO"):
        timestamp_str = time.strftime("[%H:%M:%S] ")
        self.log_text.insert(tk.END, timestamp_str + text + "\n", tag)
        self.log_text.see(tk.END)

    def _toggle_mode(self):
        if self.crypto_mode == "secure":
            self.crypto_mode = "legacy"
            self.mode_var.set("LEGACY / WEAK MODE")
            self.hash_label_name.set("MD5 (Weak)")
            self.cipher_label_name.set("DES-CBC (Weak)")
            self.log_info("[!] SWITCHED TO LEGACY / WEAK MODE (MD5 + DSS + DES-CBC)", tag="WARN")
        else:
            self.crypto_mode = "secure"
            self.mode_var.set("SECURE MODE")
            self.hash_label_name.set("SHA-512")
            self.cipher_label_name.set("AES-256-GCM")
            self.log_info("[+] SWITCHED TO SECURE MODE (SHA-512 + DSS + AES-256-GCM)", tag="PASS")

        self.config["crypto_mode"] = self.crypto_mode

    def _clear_logs(self):
        self.log_text.delete("1.0", tk.END)

    def _toggle_receiver(self):
        if not self.is_receiver_running:
            self.is_receiver_running = True
            self.btn_recv.configure(text="Stop Receiver", bg="#F38BA8")
            self.log_info("[+] Secure ARP Receiver started sniffing...", tag="PASS")
        else:
            self.is_receiver_running = False
            self.btn_recv.configure(text="Start Receiver", bg="#313244")
            self.log_info("[!] Secure ARP Receiver stopped.", tag="WARN")

    def _handle_packet_verification(self, scapy_pkt, result):
        """Process verification result dictionary and update GUI widgets."""
        status = result["status"]
        reason = result["reason"]
        details = result.get("details", {})
        msg = result.get("message")

        # Update badges based on details
        hash_status = f"✓ PASS" if details.get("hash_integrity") == "PASS" else ("❌ FAIL" if details.get("hash_integrity") == "FAIL" else "WAITING")
        dss_status = f"✓ PASS" if details.get("dss_signature") == "PASS" else ("❌ FAIL" if details.get("dss_signature") == "FAIL" else "WAITING")
        cipher_status = f"✓ PASS" if details.get("decryption") == "PASS" else ("❌ FAIL" if details.get("decryption") == "FAIL" else "WAITING")
        ts_status = f"✓ PASS" if details.get("timestamp") == "PASS" else ("❌ FAIL" if details.get("timestamp") == "FAIL" else "WAITING")
        nonce_status = f"✓ PASS" if details.get("nonce") == "PASS" else ("❌ FAIL" if details.get("nonce") == "FAIL" else "WAITING")

        self._update_badge(self.badge_hash, hash_status)
        self._update_badge(self.badge_dss, dss_status)
        self._update_badge(self.badge_cipher, cipher_status)
        self._update_badge(self.badge_ts, ts_status)
        self._update_badge(self.badge_nonce, nonce_status)

        if status == "ACCEPT":
            self.count_valid += 1
            self.lbl_valid.set(str(self.count_valid))
            sender_ip = msg.get("sender_ip") if msg else "Unknown"
            sender_mac = msg.get("sender_mac") if msg else "Unknown"
            self.log_info(f"✓ ACCEPTED: Authenticated ARP response received ({sender_ip} -> {sender_mac})", tag="PASS")
            self.log_info(f"  [+] DSS Signature & {self.crypto_mode.upper()} Hash Verified successfully.", tag="PASS")
        else:
            self.count_rejected += 1
            self.lbl_rejected.set(str(self.count_rejected))

            if "spoofing" in reason.lower() or details.get("dss_signature") == "FAIL":
                self.count_spoofing += 1
                self.lbl_spoof.set(str(self.count_spoofing))
                alert_title = "⚠ SECURITY ALERT: ARP Spoofing Detected"
            elif "replay" in reason.lower() or details.get("nonce") == "FAIL":
                self.count_replay += 1
                self.lbl_replay.set(str(self.count_replay))
                alert_title = "⚠ SECURITY ALERT: Replay Attack Detected"
            elif "integrity" in reason.lower() or details.get("hash_integrity") == "FAIL":
                self.count_tampering += 1
                self.lbl_tamper.set(str(self.count_tampering))
                alert_title = "⚠ SECURITY ALERT: Packet Tampering Detected"
            else:
                alert_title = "⚠ SECURITY ALERT: Verification Failed"

            self.log_info(f"❌ REJECTED: {reason}", tag="FAIL")
            self.log_info(f"  [!] Action: Packet dropped. ARP cache untouched.", tag="FAIL")

            # Show Popup Dialog for Attacks
            sender_ip = msg.get("sender_ip") if msg else "Unknown"
            claimed_mac = msg.get("sender_mac") if msg else "Unknown"
            messagebox.showwarning(
                alert_title,
                f"Security Verification Failed!\n\nReason: {reason}\nSender IP: {sender_ip}\nClaimed MAC: {claimed_mac}\n\nACTION: Packet REJECTED"
            )

    def _send_legitimate(self):
        """Action: Send legitimate ARP response."""
        self.log_info(f"[*] Sending Legitimate Authenticated ARP in {self.crypto_mode.upper()} mode...")
        self.config["crypto_mode"] = self.crypto_mode

        def run():
            pkt, logs = send_authenticated_arp(self.config, send_real_packet=False)
            self.last_valid_packet = pkt
            from scapy.all import Raw
            payload = pkt[Raw].load
            res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
            self.root.after(0, lambda: self._handle_packet_verification(pkt, res))

        threading.Thread(target=run, daemon=True).start()

    def _sim_spoofing(self):
        """Action: Simulate ARP Spoofing Attack."""
        self.log_info("[!] Initiating ARP Spoofing Attack simulation...", tag="WARN")
        self.config["crypto_mode"] = self.crypto_mode

        def run():
            pkt, logs = simulate_arp_spoofing(self.config)
            from scapy.all import Raw
            payload = pkt[Raw].load
            res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
            self.root.after(0, lambda: self._handle_packet_verification(pkt, res))

        threading.Thread(target=run, daemon=True).start()

    def _sim_replay(self):
        """Action: Simulate Replay Attack."""
        self.log_info("[!] Initiating Replay Attack simulation...", tag="WARN")
        self.config["crypto_mode"] = self.crypto_mode

        def run():
            pkt, logs = simulate_replay_attack(self.config, original_pkt=self.last_valid_packet)
            from scapy.all import Raw
            payload = pkt[Raw].load
            res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
            self.root.after(0, lambda: self._handle_packet_verification(pkt, res))

        threading.Thread(target=run, daemon=True).start()

    def _sim_tampering(self):
        """Action: Simulate Packet Tampering Attack."""
        self.log_info("[!] Initiating Packet Tampering Attack simulation...", tag="WARN")
        self.config["crypto_mode"] = self.crypto_mode

        def run():
            pkt, logs = simulate_tampering_attack(self.config, field_to_tamper="sender_mac", custom_value="11:22:33:44:55:66")
            from scapy.all import Raw
            payload = pkt[Raw].load
            res = verify_received_payload(payload, self.config, replay_protector=self.replay_protector)
            self.root.after(0, lambda: self._handle_packet_verification(pkt, res))

        threading.Thread(target=run, daemon=True).start()


def launch_gui(config=None):
    """Launch the Tkinter ARP Dashboard application."""
    root = tk.Tk()
    app = ARPDashboardApp(root, config=config)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
