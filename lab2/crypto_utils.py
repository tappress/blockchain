"""Crypto helpers for CNUCoin: RSA digital signatures and MD5 hashing."""

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


RSA_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_rsa_keypair():
    """Generate an RSA private/public keypair. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def derive_user_id(public_pem: bytes) -> str:
    """User ID = single MD5 hash of the public key (per lab spec)."""
    return md5_hex(public_pem)


def sign_data(private_pem: bytes, data: bytes) -> bytes:
    """Sign data with RSA-PSS + SHA-256."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS + SHA-256 signature. Returns True/False."""
    from cryptography.exceptions import InvalidSignature

    public_key = serialization.load_pem_public_key(public_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
