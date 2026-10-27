"""
Key Generation Utility for Cryptographically Authenticated ARP.
Generates DSA 2048-bit key pairs for DSS digital signatures
and shared secret keys for AES-GCM (256-bit) and DES-CBC (64-bit).
"""

import os
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes

KEYS_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_all_keys(target_dir=KEYS_DIR):
    """Generate all required asymmetric and symmetric keys into target_dir."""
    os.makedirs(target_dir, exist_ok=True)

    roles = ["gateway", "victim", "attacker"]

    for role in roles:
        priv_path = os.path.join(target_dir, f"{role}_private.pem")
        pub_path = os.path.join(target_dir, f"{role}_public.pem")

        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            print(f"[*] Generating 2048-bit DSA key pair for '{role}'...")
            key = DSA.generate(2048)
            private_pem = key.export_key(format="PEM")
            public_pem = key.publickey().export_key(format="PEM")

            with open(priv_path, "wb") as f:
                f.write(private_pem)
            with open(pub_path, "wb") as f:
                f.write(public_pem)
            print(f"  [+] Saved: {priv_path}")
            print(f"  [+] Saved: {pub_path}")
        else:
            print(f"[=] Keys for '{role}' already exist.")

    # AES 256-bit (32 bytes) key
    aes_key_path = os.path.join(target_dir, "shared_aes.key")
    if not os.path.exists(aes_key_path):
        aes_key = get_random_bytes(32)
        with open(aes_key_path, "wb") as f:
            f.write(aes_key)
        print(f"  [+] Saved AES 256-bit shared key: {aes_key_path}")

    # DES 64-bit (8 bytes) key
    des_key_path = os.path.join(target_dir, "shared_des.key")
    if not os.path.exists(des_key_path):
        des_key = get_random_bytes(8)
        with open(des_key_path, "wb") as f:
            f.write(des_key)
        print(f"  [+] Saved DES 64-bit shared key: {des_key_path}")


def load_dsa_key(role, key_type="public", target_dir=KEYS_DIR):
    """Load a DSA PEM key for a given role ('gateway', 'victim', 'attacker') and key_type ('public' or 'private')."""
    key_path = os.path.join(target_dir, f"{role}_{key_type}.pem")
    if not os.path.exists(key_path):
        # Generate on demand if missing
        generate_all_keys(target_dir)
    with open(key_path, "rb") as f:
        return f.read()


def load_symmetric_key(algo="aes", target_dir=KEYS_DIR):
    """Load symmetric key for AES or DES."""
    key_path = os.path.join(target_dir, f"shared_{algo.lower()}.key")
    if not os.path.exists(key_path):
        generate_all_keys(target_dir)
    with open(key_path, "rb") as f:
        return f.read()


if __name__ == "__main__":
    generate_all_keys()
    print("[✓] All cryptographic key pairs successfully initialized.")
