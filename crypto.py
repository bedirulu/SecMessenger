"""
SecMessenger — Crypto Core
--------------------------
Hybrid RSA-2048 + AES-256-GCM encryption.

Payload format (binary):
  [2 bytes big-endian]  length of RSA-encrypted AES key
  [N bytes]             RSA-OAEP encrypted AES-256 key
  [12 bytes]            AES-GCM nonce
  [remaining]           AES-GCM ciphertext + 16-byte auth tag

The recipient's MAC address is used as AAD (Additional Authenticated Data),
so any file renamed/forwarded to a different device will fail decryption.
"""

import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Key generation ─────────────────────────────────────────────────────────

def generate_keypair(password: str | None = None) -> tuple[bytes, bytes]:
    """
    Generate an RSA-2048 key pair.

    Args:
        password: Optional passphrase to protect the private key.

    Returns:
        (private_pem, public_pem) as bytes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ── Hybrid encryption ───────────────────────────────────────────────────────

def hybrid_encrypt(
    message: bytes,
    public_key_pem: bytes,
    mac_hint: str,
) -> bytes:
    """
    Encrypt *message* for the owner of *public_key_pem*.

    The normalised *mac_hint* (target device MAC) is bound into the
    ciphertext as AAD so the file cannot be decrypted on a different device.

    Returns the raw encrypted payload.
    """
    mac_hint_norm = _normalise_mac(mac_hint)

    pub_key = serialization.load_pem_public_key(public_key_pem)

    # 1. Random AES-256 session key + nonce
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    # 2. Encrypt message with AES-256-GCM (MAC as AAD)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, message, mac_hint_norm.encode())

    # 3. Encrypt the session key with RSA-OAEP
    enc_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 4. Pack: [2B key len][enc AES key][12B nonce][ciphertext+tag]
    header = struct.pack(">H", len(enc_aes_key))
    return header + enc_aes_key + nonce + ciphertext


def hybrid_decrypt(
    payload: bytes,
    private_key_pem: bytes,
    password: str | None,
    mac_hint: str,
) -> str:
    """
    Decrypt a payload produced by *hybrid_encrypt*.

    Args:
        payload:          Raw bytes from the .enc file.
        private_key_pem:  PEM-encoded private key.
        password:         Passphrase if the key is protected, else None.
        mac_hint:         The local device MAC address (must match the one
                          used during encryption).

    Returns:
        The decrypted plaintext as a string.

    Raises:
        ValueError:  If MAC does not match (AAD authentication failure).
        Exception:   On wrong key / corrupted payload.
    """
    mac_hint_norm = _normalise_mac(mac_hint)

    priv_key = serialization.load_pem_private_key(
        private_key_pem,
        password=password.encode() if password else None,
    )

    # Unpack header
    (rsa_key_len,) = struct.unpack(">H", payload[:2])
    enc_aes_key = payload[2 : 2 + rsa_key_len]
    nonce = payload[2 + rsa_key_len : 2 + rsa_key_len + 12]
    ciphertext = payload[2 + rsa_key_len + 12 :]

    # Recover AES session key
    aes_key = priv_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Decrypt + verify AAD
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, mac_hint_norm.encode())
    except Exception:
        raise ValueError(
            "Kimlik doğrulama başarısız — MAC uyuşmuyor veya dosya bozulmuş."
        )

    return plaintext.decode("utf-8")


# ── Helpers ─────────────────────────────────────────────────────────────────

def _normalise_mac(mac: str) -> str:
    """Strip separators and upper-case a MAC address."""
    return mac.upper().replace(":", "").replace("-", "")


def mac_to_filename(mac: str) -> str:
    return _normalise_mac(mac)
