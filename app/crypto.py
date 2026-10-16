"""Key generation, encryption at rest and signed tokens."""

import base64
import hashlib
import hmac
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import get_settings


@lru_cache
def _fernet() -> Fernet:
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"dkim-key-encryption"
    ).derive(get_settings().secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def generate_dkim_keypair(bits: int = 2048) -> tuple[bytes, str]:
    """Return (private key PEM, DNS TXT record value)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, dkim_txt_record(pub)


def dkim_txt_record(public_der: bytes) -> str:
    return f"v=DKIM1; k=rsa; p={base64.b64encode(public_der).decode()}"


def public_record_from_pem(pem: bytes) -> str:
    key = serialization.load_pem_private_key(pem, password=None)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return dkim_txt_record(der)


# --- Signed, expiring tokens for email links ---------------------------------


def _serializer(salt: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt=salt)


def make_token(purpose: str, data) -> str:
    return _serializer(purpose).dumps(data)


def read_token(purpose: str, token: str, max_age: int):
    """Return the payload, or None if the token is bad or expired."""
    try:
        return _serializer(purpose).loads(token, max_age=max_age)
    except (SignatureExpired, BadSignature):
        return None


# --- Short MACs for bounce addresses ----------------------------------------


def short_mac(value: str, length: int = 8) -> str:
    digest = hmac.new(get_settings().secret_key.encode(), value.encode(), hashlib.sha256)
    return base64.b32encode(digest.digest()).decode().lower()[:length]
