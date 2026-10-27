# Cryptographically Authenticated ARP for ARP Spoofing Prevention

A complete, production-grade Python solution implementing a **Cryptographically Authenticated Address Resolution Protocol (ARP)** architecture designed to eliminate ARP cache poisoning and ARP spoofing attacks in local area networks (LANs).

---

## 1. PROJECT OBJECTIVE & PROBLEM STATEMENT

### The Problem with Traditional ARP
The standard Address Resolution Protocol (RFC 826) operates without state or authentication. When a host sends an ARP Request broadcast (`Who has 192.168.56.1?`), any host on the same LAN can transmit an unauthenticated ARP Reply claiming:

```text
Gateway IP (192.168.56.1) → Attacker MAC (11:22:33:44:55:66)
```

Receiving hosts unconditionally accept unsolicited ARP replies and update their ARP cache tables, allowing an attacker to perform Man-In-The-Middle (MITM) eavesdropping, session hijacking, or Denial-of-Service (DoS) attacks.

### Proposed Cryptographic Solution
This project introduces a **Cryptographically Authenticated ARP Architecture** that attaches a signed, encrypted payload envelope inside ARP packets.

```text
                    SECURE SENDER WORKFLOW
                    +--------------------+
                    |  ARP Information   |
                    | (IP, MAC, TS, Nonce|
                    +---------+----------+
                              |
                              v
                        [ SHA-512 ] (Canonical Message Hash)
                              |
                              v
                      [ DSS Signature ] (Sender Private Key)
                              |
                              v
                     [ AES-256 Encryption ] (Symmetric Confidentiality)
                              |
                              v
                     [ Network Packet ] (Scapy Ether/ARP/Raw)
                              |
                              +--------------------------+
                                                         |
                    RECEIVER VERIFICATION PIPELINE       |
                    +------------------------------+     |
                    |  Received Network Packet     |<----+
                    +--------------+---------------+
                                   |
                                   v
                        [ AES-256 Decryption ]
                                   |
                                   v
                        [ DSS Verification ] (Sender Public Key)
                                   |
                                   v
                      [ SHA-512 Hash Check ] (Integrity Check)
                                   |
                                   v
                      [ Timestamp & Nonce Check ] (Replay Protection)
                                   |
                        +----------+----------+
                        |                     |
                        v                     v
                   [ ACCEPT ]            [ REJECT ]
               Update ARP Cache       Security Alert
```

---

## 2. CRYPTOGRAPHIC ARCHITECTURE

### Strong / Secure Mode
- **Integrity**: **SHA-512** produces a 512-bit message digest of the canonical string format:
  `sender_ip|sender_mac|target_ip|target_mac|timestamp|nonce`
- **Authentication & Non-Repudiation**: **DSS (Digital Signature Standard)** using **2048-bit DSA keys** (`fips-186-3`) signs the SHA-512 digest using the sender's private key. The receiver verifies the signature using the sender's public key.
- **Confidentiality**: **AES-256-GCM** (Galois/Counter Mode) encrypts the authenticated payload envelope with randomized 96-bit nonces and 128-bit authentication tags.

### Legacy / Weak Mode (For Educational Comparison)
- **Integrity**: **MD5** (128-bit digest), included strictly to demonstrate collision-prone, obsolete hashing.
- **Authentication**: **DSS** performs signature verification in both modes.
- **Confidentiality**: **DES-CBC** (Data Encryption Standard in Cipher Block Chaining mode with PKCS7 padding, 56-bit effective key size).

> [!IMPORTANT]
> **Educational Clarification**: Replacing SHA-512 with MD5 does **NOT** bypass DSS digital signatures. DSS performs signature verification in both modes. However, MD5 is cryptographically broken due to collision vulnerabilities, and DES has an inadequate key size against modern hardware brute-force attacks. If DSS signature verification fails in either mode, the packet is immediately **REJECTED**.

---

## 3. THREE-VM ARCHITECTURE (LAB SETUP)

This project is built for demonstration across **3 isolated VirtualBox or VMware Virtual Machines**:

```text
   +-----------------------+              +-----------------------+
   |   VM 1: SENDER /      |              |  VM 2: RECEIVER /     |
   |   VICTIM GATEWAY      |              |   VERIFIER HOST       |
   |   IP: 192.168.56.10   |              |   IP: 192.168.56.20   |
   |   MAC: 08:00:27:11:22:33|              |   MAC: 08:00:27:AA:BB|
   +-----------+-----------+              +-----------+-----------+
               |                                      |
               +-------------------+------------------+
                                   |
                       +-----------+-----------+
                       |   VM 3: ATTACKER      |
                       |   KALI LINUX NODE     |
                       |   IP: 192.168.56.30   |
                       |   MAC: 11:22:33:44:55|
                       +-----------------------+
```

### VM 1 — Sender / Victim (`192.168.56.10`)
Runs the agent in Sender mode (`python main.py --mode sender`). Constructs, hashes, signs, encrypts, and transmits authenticated ARP packets.

### VM 2 — Receiver / Verifier (`192.168.56.20`)
Runs the agent in Receiver or GUI mode (`python main.py --mode receiver` or `python main.py --mode gui`). Captures packets, decrypts payload, verifies DSS signatures, checks hash integrity, enforces replay protection, updates local ARP table on success, or triggers security alerts on failure.

### VM 3 — Kali Linux Attacker (`192.168.56.30`)
Used inside the isolated lab network to simulate ARP Spoofing (unauthorized MAC claim), Replay Attacks (re-sending cached packets), and Packet Tampering.

---

## 4. INSTALLATION & SETUP

### Step 1: Clone or Extract Repository
```bash
cd cryptographic-arp
```

### Step 2: Set Up Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Initialize Cryptographic Keys
```bash
python3 keys/generate_keys.py
```
This command auto-generates 2048-bit DSA key pairs (`gateway_*.pem`, `victim_*.pem`, `attacker_*.pem`) and symmetric keys (`shared_aes.key`, `shared_des.key`) in the `keys/` directory.

---

## 5. RUNNING THE AGENT

### Running GUI Dashboard (Recommended)
```bash
python3 main.py --mode gui
```

### Running via Command Line

#### Sender Instance (VM 1)
```bash
python3 main.py --mode sender --crypto-mode secure --interface eth0
```

#### Receiver Instance (VM 2)
```bash
python3 main.py --mode receiver --crypto-mode secure --interface eth0
```

#### Attack Simulation (VM 3)
```bash
# ARP Spoofing Attack
python3 main.py --mode attack --attack-type spoofing

# Replay Attack
python3 main.py --mode attack --attack-type replay

# Packet Tampering Attack
python3 main.py --mode attack --attack-type tampering
```

---

## 6. REPLAY & TAMPER PROTECTION DEMONSTRATION

1. **Replay Protection**: Each message includes a timestamp and a 128-bit cryptographically random `nonce`. The receiver maintains a nonce cache (`ReplayProtector`). If an attacker re-transmits an identical valid packet, the receiver detects the reused nonce and rejects it with:
   `❌ MESSAGE REJECTED: Nonce already used (Replay Attack Detected)`
2. **Timestamp Drift Validation**: Messages older than 60 seconds (configurable via `timestamp_max_drift`) are rejected as stale.
3. **Packet Tampering**: Modifying any parameter (`sender_ip`, `sender_mac`, `target_ip`, `target_mac`) post-signature invalidates both the SHA-512 hash and DSS signature verification.

---

## 7. WIRESHARK INSPECTION GUIDE

To inspect authenticated ARP traffic in Wireshark:

1. Launch Wireshark on the VM network interface (e.g., `vboxnet0` or `eth0`).
2. Apply the display filter: `arp`.
3. Capture traffic while sending a packet in **Secure Mode**. Inspect the packet structure:
   - **Ethernet Header**: Source MAC & Destination MAC.
   - **ARP Header**: Standard ARP reply (`op=2`).
   - **Data / Raw Payload**: Encrypted JSON payload containing Base64 ciphertext (`AES-GCM`). A passive eavesdropper cannot read the plaintext ARP binding parameters.
4. Switch to **Legacy Mode** and capture traffic:
   - Observe that **DES-CBC** is used. While encrypted, DES is vulnerable to brute-force key recovery with modern compute capabilities.

---

## 8. AUTOMATED TEST SUITE

Run the full automated test suite covering all 9 required test cases:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

### Test Coverage Summary:
- `Test 1: Valid Message` -> **PASS**
- `Test 2: Modified Sender MAC` -> **FAIL** (DSS & Hash check fail)
- `Test 3: Modified Sender IP` -> **FAIL** (DSS & Hash check fail)
- `Test 4: Invalid Signature` -> **FAIL** (Attacker key signature rejected)
- `Test 5: Expired Timestamp` -> **FAIL** (Stale timestamp rejected)
- `Test 6: Reused Nonce` -> **FAIL** (Replay attack rejected)
- `Test 7: Modified Ciphertext` -> **FAIL** (AES GCM tag validation error)
- `Test 8: Legacy MD5 Mode` -> **PASS** (Demonstrates MD5 hashing pipeline)
- `Test 9: Legacy DES Mode` -> **PASS** (Demonstrates DES-CBC cipher pipeline)

---

## 9. VIVA VOCE QUESTIONS & ANSWERS

### Q1: What is ARP and why is traditional ARP vulnerable?
**Answer**: ARP (Address Resolution Protocol) resolves IP addresses to physical MAC addresses on a LAN. Traditional ARP is stateless and unauthenticated—hosts accept any ARP reply, allowing attackers to send forged ARP responses and poison the target's ARP cache table.

### Q2: What is ARP Spoofing / ARP Poisoning?
**Answer**: ARP Spoofing occurs when an attacker transmits forged ARP responses claiming that the Gateway's IP address maps to the attacker's MAC address, directing all network traffic through the attacker's machine.

### Q3: What is the core cryptographic pipeline of this project?
**Answer**:
1. Canonical Message formatting (`sender_ip|sender_mac|target_ip|target_mac|timestamp|nonce`).
2. **SHA-512** hash digest computation.
3. **DSS (DSA 2048-bit)** digital signature generation using sender private key.
4. **AES-256-GCM** encryption of the envelope package.
5. Scapy network transmission.
6. AES decryption, DSS signature verification using sender public key, SHA-512 hash comparison, and Timestamp/Nonce validation on the receiver.

### Q4: Why did you choose SHA-512 over MD5?
**Answer**: SHA-512 is a secure cryptographic hash function producing a 512-bit digest resistant to collision attacks. MD5 is cryptographically broken and vulnerable to collision attacks where two different inputs produce the exact same hash.

### Q5: What is DSS and why is a digital signature necessary?
**Answer**: DSS (Digital Signature Standard) uses asymmetric cryptography (DSA) to provide authentication, integrity, and non-repudiation. A digital signature ensures that only the legitimate owner of the private key could have generated the ARP response.

### Q6: What role does AES encryption play in this system?
**Answer**: AES (Advanced Encryption Standard in GCM mode) provides confidentiality and payload authenticity, preventing passive network sniffing of custom authenticated ARP attributes and preventing payload tampering.

### Q7: Why did you include Legacy Mode with MD5 and DES?
**Answer**: Legacy Mode is included strictly for educational comparative analysis to demonstrate weak, obsolete cryptography (MD5 collision risk, DES 56-bit key length weakness) versus modern standards (SHA-512 and AES-256-GCM).

### Q8: Does switching to MD5 bypass DSS digital signature verification?
**Answer**: No. DSS signature verification is performed independently in both modes. If DSS verification fails, the packet is rejected regardless of whether SHA-512 or MD5 was used.

### Q9: What is Replay Protection and how is it implemented?
**Answer**: Replay protection prevents an attacker from recording a valid signed ARP packet and retransmitting it later. It is enforced using a timestamp drift limit (max 60 seconds) and a unique random `nonce` cached by the receiver (`ReplayProtector`).

### Q10: Why is a nonce required alongside a timestamp?
**Answer**: A timestamp alone allows replay attacks within the valid time window (e.g. within 60 seconds). The nonce guarantees that every single transmission is uniquely identified and cannot be processed twice even within the same second.

### Q11: Why can't an attacker generate a valid DSS signature for the Gateway?
**Answer**: Because DSS requires the Gateway's private key (`gateway_private.pem`). The attacker only has access to their own private key (`attacker_private.pem`). When the receiver verifies the signature against the Gateway's public key (`gateway_public.pem`), mathematical verification fails.

### Q12: What happens if an attacker modifies the sender MAC in a signed packet?
**Answer**: Modifying any parameter alters the canonical representation. When the receiver computes the SHA-512 hash and verifies the DSS signature, the signature verification fails and the packet is immediately rejected.

### Q13: Is this system intended as a drop-in replacement for standard ARP?
**Answer**: No. This is a prototype authenticated extension demonstrating cryptographically backed ARP mapping. Standard ARP frames do not natively include encrypted payload headers.

### Q14: How would key management be handled in a real production enterprise network?
**Answer**: In production, public keys would be distributed using a Public Key Infrastructure (PKI) with X.509 digital certificates signed by an internal Certificate Authority (CA) or integrated with 802.1X network access control.

### Q15: What are the main performance overheads of this approach?
**Answer**: Computation overhead (asymmetric DSA signing and verification) and network payload overhead (attaching DSS signatures and ciphertext into frame envelopes).

### Q16: How does this project compare to enterprise switch security mechanisms like DAI?
**Answer**: Enterprise switches use **Dynamic ARP Inspection (DAI)** and **DHCP Snooping** at Layer 2 to validate ARP packets against a trusted binding database. Our cryptographic solution enforces authentication end-to-end at the host software level without requiring specialized managed switch hardware.

### Q17: How does the Tkinter Dashboard help in security monitoring?
**Answer**: The dashboard visualizes real-time status badges for every step of the verification pipeline (SHA-512/MD5, DSS, AES/DES, Timestamp, Nonce), displays live scrolling security audit logs, triggers alert dialogs during attack attempts, and maintains event counters for security metrics.

---

## 10. PROJECT STRUCTURE

```text
cryptographic-arp/
├── main.py                     # Entry point for CLI & GUI modes
├── config.py                   # Configuration loader & CLI parser
├── config.yaml                 # Network & cryptographic parameters
├── requirements.txt            # Python dependencies (pycryptodome, scapy, pyyaml)
├── README.md                   # Complete documentation & Viva Q&A
├── crypto/
│   ├── __init__.py
│   ├── hashing.py              # SHA-512, MD5, Canonical Representation
│   ├── dss.py                  # PyCryptodome DSS Signature Sign/Verify
│   ├── aes_crypto.py           # AES-256-GCM Encryption/Decryption
│   └── des_crypto.py           # DES-CBC Encryption/Decryption
├── arp/
│   ├── __init__.py
│   ├── message.py              # AuthenticatedARPMessage class & JSON serialization
│   ├── sender.py               # Sender Workflow (Steps 1-7)
│   ├── receiver.py             # Receiver Verification Engine (Steps 1-9)
│   └── replay_protection.py    # Timestamp & Nonce cache manager
├── attacks/
│   ├── __init__.py
│   ├── spoofing.py             # ARP Spoofing simulator
│   ├── replay.py               # Replay Attack simulator
│   └── tampering.py            # Packet Tampering simulator
├── gui/
│   ├── __init__.py
│   └── dashboard.py            # Tkinter Security Dashboard GUI
├── keys/
│   ├── generate_keys.py        # DSA 2048-bit & Symmetric Key generator
│   └── README.md               # Key management rules & PKI overview
└── tests/
    ├── __init__.py
    ├── test_crypto.py          # Hashing, DSS, AES, DES unit tests
    ├── test_authentication.py  # Tests 1, 2, 3, 4, 7 (Integrity & Signatures)
    ├── test_replay.py          # Tests 5 & 6 (Timestamp & Nonce Replay)
    └── test_attacks.py         # Tests 8 & 9 (Legacy MD5/DES mode)
```

---

## 11. LICENSE & DISCLAIMER

This software is developed strictly for **educational and research purposes** in network and cybersecurity courses. It must be operated inside isolated virtual laboratory environments (VirtualBox / VMware). Do NOT use this software against external, un-authorized networks.
