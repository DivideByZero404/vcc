"""
Secure S3 Upload — Component 4: Confidentiality & Integrity.
Encrypts files with AES-256-GCM before upload and attaches SHA-256 integrity metadata.
On download, verifies SHA-256 hash and decrypts.
"""

import os
import json
import hashlib
import base64
import boto3
from botocore.exceptions import ClientError
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _derive_key(password: str) -> bytes:
    """Derive a 256-bit AES key from a password using SHA-256."""
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt_file_aes256(file_bytes: bytes, key: bytes) -> dict:
    """
    Encrypt file bytes with AES-256-GCM.
    Returns dict with base64-encoded ciphertext, nonce, and tag.
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def decrypt_file_aes256(cipher_dict: dict, key: bytes) -> bytes:
    """Decrypt AES-256-GCM encrypted dict back to original bytes."""
    ciphertext = base64.b64decode(cipher_dict["ciphertext"])
    nonce = base64.b64decode(cipher_dict["nonce"])
    tag = base64.b64decode(cipher_dict["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def secure_upload(bucket_name: str, file_bytes: bytes, filename: str, password: str, region: str = "us-east-1"):
    """
    Encrypt file with AES-256-GCM, compute SHA-256 integrity hash,
    then upload encrypted payload to S3 with integrity metadata.

    Returns (success: bool, message: str, metadata: dict)
    """
    key = _derive_key(password)

    # Compute SHA-256 of original plaintext for integrity verification
    original_sha256 = compute_sha256(file_bytes)

    # Encrypt
    cipher_dict = encrypt_file_aes256(file_bytes, key)

    # Build upload payload: JSON envelope containing cipher data + integrity hash
    envelope = {
        "filename": filename,
        "sha256_original": original_sha256,
        "encryption": "AES-256-GCM",
        "cipher": cipher_dict
    }
    envelope_bytes = json.dumps(envelope).encode("utf-8")

    # S3 object key: store as .enc file
    s3_key = f"secure/{filename}.enc"

    s3 = boto3.client("s3", region_name=region)
    try:
        s3.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=envelope_bytes,
            ContentType="application/octet-stream",
            Metadata={
                "x-original-filename": filename,
                "x-sha256-original": original_sha256,
                "x-encryption": "AES-256-GCM"
            }
        )
        return True, f"File '{filename}' encrypted and uploaded as '{s3_key}'.", {
            "s3_key": s3_key,
            "original_filename": filename,
            "sha256_original": original_sha256,
            "encryption": "AES-256-GCM",
            "size_bytes": len(envelope_bytes)
        }
    except ClientError as e:
        return False, str(e), {}


def secure_download(bucket_name: str, s3_key: str, password: str, region: str = "us-east-1"):
    """
    Download encrypted file from S3, verify SHA-256 integrity, and decrypt.

    Returns (success: bool, message: str, file_bytes: bytes or None, metadata: dict)
    """
    key = _derive_key(password)
    s3 = boto3.client("s3", region_name=region)

    try:
        response = s3.get_object(Bucket=bucket_name, Key=s3_key)
        envelope_bytes = response["Body"].read()
    except ClientError as e:
        return False, str(e), None, {}

    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"))
        stored_sha256 = envelope["sha256_original"]
        cipher_dict = envelope["cipher"]
        original_filename = envelope.get("filename", s3_key)
    except Exception as e:
        return False, f"Envelope parse error: {e}", None, {}

    # Decrypt
    try:
        plaintext = decrypt_file_aes256(cipher_dict, key)
    except Exception as e:
        return False, f"Decryption failed (wrong password or tampered data): {e}", None, {}

    # Verify SHA-256 integrity
    computed_sha256 = compute_sha256(plaintext)
    if computed_sha256 != stored_sha256:
        return False, f"INTEGRITY VIOLATION: SHA-256 mismatch! File may have been tampered.", None, {
            "stored_sha256": stored_sha256,
            "computed_sha256": computed_sha256
        }

    return True, f"File '{original_filename}' decrypted and integrity verified.", plaintext, {
        "original_filename": original_filename,
        "sha256_verified": computed_sha256,
        "size_bytes": len(plaintext)
    }


def list_secure_files(bucket_name: str, region: str = "us-east-1"):
    """List all encrypted files in the secure/ prefix."""
    s3 = boto3.client("s3", region_name=region)
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix="secure/")
        files = []
        for obj in response.get("Contents", []):
            meta_resp = s3.head_object(Bucket=bucket_name, Key=obj["Key"])
            meta = meta_resp.get("Metadata", {})
            files.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].strftime("%Y-%m-%d %H:%M:%S"),
                "original_filename": meta.get("x-original-filename", obj["Key"]),
                "sha256": meta.get("x-sha256-original", "N/A"),
                "encryption": meta.get("x-encryption", "AES-256-GCM")
            })
        return files, f"{len(files)} encrypted file(s) found."
    except ClientError as e:
        return [], str(e)
