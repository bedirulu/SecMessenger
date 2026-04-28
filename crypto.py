"""
SecMessenger v3.0 — crypto.py
-------------------------------
• RSA-2048 + AES-256-GCM hibrit şifreleme
• MAC adresi kimlik doğrulama (payload içinde HMAC ile)
• Şifre korumalı private key desteği
• Güvenli anahtar türetme (PBKDF2-HMAC-SHA256)
"""

import os
import hmac
import struct
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ═══════════════════════════════════════════════════════════
#  Sabitler
# ═══════════════════════════════════════════════════════════

RSA_KEY_SIZE   = 2048
AES_KEY_SIZE   = 32        # 256-bit
GCM_NONCE_SIZE = 12        # 96-bit (GCM standardı)
HMAC_SIZE      = 32        # SHA-256 çıktısı
RSA_BLOCK_SIZE = 256       # RSA-2048 → 256 byte şifreli blok

# Payload formatı (binary):
# [ RSA_BLOCK (256 byte) ][ GCM_NONCE (12 byte) ][ MAC_HMAC (32 byte) ][ CIPHERTEXT ]
# RSA_BLOCK içinde: AES key (32 byte) şifrelenmiş


# ═══════════════════════════════════════════════════════════
#  MAC Adresi Yardımcıları
# ═══════════════════════════════════════════════════════════

def mac_to_filename(mac: str) -> str:
    """MAC adresini dosya adı için normalize eder: XX:XX:XX → XXXXXXXXXXXX"""
    return mac.upper().replace(":", "").replace("-", "")


def _mac_to_bytes(mac: str) -> bytes:
    return mac_to_filename(mac).encode("ascii")


# ═══════════════════════════════════════════════════════════
#  Anahtar Üretimi
# ═══════════════════════════════════════════════════════════

def generate_keypair(password: str | None = None) -> tuple[bytes, bytes]:
    """
    RSA-2048 anahtar çifti üretir.
    password verilirse private key AES-256-CBC + PBKDF2 ile şifrelenir.

    Returns:
        (private_pem, public_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

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


# ═══════════════════════════════════════════════════════════
#  Hibrit Şifreleme
# ═══════════════════════════════════════════════════════════

def hybrid_encrypt(plaintext: bytes, public_pem: bytes, target_mac: str) -> bytes:
    """
    1. Rastgele 256-bit AES anahtarı üret
    2. AES-GCM ile mesajı şifrele
    3. AES anahtarını alıcının RSA public key'i ile şifrele
    4. Hedef MAC adresinin HMAC'ini payload'a göm (kimlik kilidi)

    Payload: RSA_BLOCK | GCM_NONCE | MAC_HMAC | CIPHERTEXT
    """
    # AES oturumu
    aes_key = os.urandom(AES_KEY_SIZE)
    nonce   = os.urandom(GCM_NONCE_SIZE)

    # MAC HMAC — AES key'den türetilir, hedef MAC'e bağlar
    mac_hmac = _compute_mac_hmac(aes_key, target_mac)

    # Mesajı şifrele (GCM authenticated encryption)
    aesgcm     = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, mac_hmac)  # AAD = mac_hmac

    # AES anahtarını RSA ile şifrele
    pub_key   = serialization.load_pem_public_key(public_pem)
    rsa_block = pub_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return rsa_block + nonce + mac_hmac + ciphertext


# ═══════════════════════════════════════════════════════════
#  Hibrit Şifre Çözme
# ═══════════════════════════════════════════════════════════

def hybrid_decrypt(
    payload: bytes,
    private_pem: bytes,
    password: str | None,
    local_mac: str,
) -> str:
    """
    1. Payload'ı parçalara ayır
    2. RSA private key ile AES anahtarını çöz
    3. MAC HMAC'ini doğrula (cihaz kimliği kontrolü)
    4. AES-GCM ile mesajı çöz

    Returns:
        Düz metin (str)

    Raises:
        ValueError: MAC uyuşmazlığı veya bütünlük hatası
    """
    if len(payload) < RSA_BLOCK_SIZE + GCM_NONCE_SIZE + HMAC_SIZE:
        raise ValueError("Geçersiz payload boyutu.")

    # Payload'ı ayır
    rsa_block  = payload[:RSA_BLOCK_SIZE]
    nonce      = payload[RSA_BLOCK_SIZE : RSA_BLOCK_SIZE + GCM_NONCE_SIZE]
    mac_hmac   = payload[RSA_BLOCK_SIZE + GCM_NONCE_SIZE : RSA_BLOCK_SIZE + GCM_NONCE_SIZE + HMAC_SIZE]
    ciphertext = payload[RSA_BLOCK_SIZE + GCM_NONCE_SIZE + HMAC_SIZE :]

    # Private key yükle
    pw_bytes = password.encode("utf-8") if password else None
    priv_key = serialization.load_pem_private_key(private_pem, password=pw_bytes)

    # RSA ile AES anahtarını çöz
    try:
        aes_key = priv_key.decrypt(
            rsa_block,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise ValueError("RSA şifre çözme başarısız — yanlış private key.")

    # MAC doğrula
    expected_hmac = _compute_mac_hmac(aes_key, local_mac)
    if not hmac.compare_digest(expected_hmac, mac_hmac):
        raise ValueError(
            "MAC adresi uyuşmazlığı — bu dosya bu cihaz için şifrelenmemiş."
        )

    
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, mac_hmac)
    except Exception:
        raise ValueError("AES-GCM doğrulama başarısız — dosya değiştirilmiş olabilir.")

    return plaintext.decode("utf-8")



def _compute_mac_hmac(aes_key: bytes, mac: str) -> bytes:
    """AES key + MAC adresinden deterministik HMAC üretir."""
    return hmac.new(
        aes_key,
        _mac_to_bytes(mac),
        hashlib.sha256,
    ).digest()
