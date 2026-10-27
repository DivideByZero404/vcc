# Key Management Documentation

This directory contains the cryptographic key material used by the **Cryptographically Authenticated ARP** framework.

## Key Files Overview

- `gateway_private.pem` / `gateway_public.pem`: 2048-bit DSA key pair for the legitimate Gateway (VM 1 / Sender).
- `victim_private.pem` / `victim_public.pem`: 2048-bit DSA key pair for the Verifier Node (VM 2 / Receiver).
- `attacker_private.pem` / `attacker_public.pem`: 2048-bit DSA key pair generated for attack simulation (VM 3 Attacker).
- `shared_aes.key`: 256-bit (32 bytes) symmetric key for AES-GCM authenticated encryption in Secure Mode.
- `shared_des.key`: 64-bit (8 bytes) symmetric key for DES-CBC encryption in Legacy Mode.

## Security Practices & Rules

1. **Private Key Confidentiality**: Private keys (`*_private.pem`) must NEVER be transmitted over the network or exposed in public code repositories.
2. **Public Key Distribution**: In this educational lab setup, public keys are stored locally. In a production enterprise network, public keys would be distributed via a **Public Key Infrastructure (PKI)** or signed certificates issued by a trusted Certificate Authority (CA).
3. **No Hardcoded Keys**: All cryptographic keys are loaded dynamically from PEM and binary key files using `keys/generate_keys.py`.

## Regenerating Keys

To reset or regenerate all key files, execute:

```bash
python3 keys/generate_keys.py
```
