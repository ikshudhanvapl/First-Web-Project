"""
crypto.py — RSA keypair management and JWKS endpoint.

Why RS256 over HS256:
  - HS256 is symmetric: any service that can VERIFY a token can also FORGE one.
    This means every microservice must share the secret — a major blast radius.
  - RS256 is asymmetric: we sign with the PRIVATE key (kept only in this service),
    other services verify with the PUBLIC key (safe to distribute freely).
  - The JWKS endpoint (/.well-known/jwks.json) lets any service discover and
    cache the public key automatically — standard OAuth 2.0 / OIDC pattern.

Key lifecycle:
  - On first boot, generate a 2048-bit RSA keypair and persist to disk.
  - On subsequent boots, load the existing keypair (stable kid across restarts).
  - In production, mount the private key from a Vault secret or K8s secret,
    not the local filesystem.
"""

import json
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from jose import jwt as jose_jwt
from jose.utils import base64url_encode
import base64

# ── Key storage paths ────────────────────────────────────────────────────────
_KEY_DIR = Path(os.getenv("KEY_DIR", "/app/keys"))
_PRIVATE_KEY_PATH = _KEY_DIR / "private.pem"
_PUBLIC_KEY_PATH  = _KEY_DIR / "public.pem"
_KID_PATH         = _KEY_DIR / "kid.txt"   # stable key ID across restarts

# Module-level key cache
_private_key = None
_public_key  = None
_kid: str    = ""
_jwks_cache: dict = {}


def _generate_keypair() -> None:
    """Generate a fresh RSA-2048 keypair and persist it."""
    _KEY_DIR.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Write private key (PEM, no passphrase — use Vault in production)
    _PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _PRIVATE_KEY_PATH.chmod(0o600)

    # Write public key
    _PUBLIC_KEY_PATH.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    # Generate a stable kid (key ID)
    _KID_PATH.write_text(str(uuid.uuid4()))


def init_keys() -> None:
    """Load or generate the RSA keypair. Call once at app startup."""
    global _private_key, _public_key, _kid, _jwks_cache

    if not _PRIVATE_KEY_PATH.exists():
        _generate_keypair()

    _private_key = serialization.load_pem_private_key(
        _PRIVATE_KEY_PATH.read_bytes(),
        password=None,
        backend=default_backend(),
    )
    _public_key = _private_key.public_key()
    _kid = _KID_PATH.read_text().strip()

    # Pre-build the JWKS response (expensive to compute, cheap to cache)
    _jwks_cache = _build_jwks()


def _int_to_base64url(n: int) -> str:
    """Convert a large integer (RSA modulus/exponent) to base64url."""
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(
        n.to_bytes(length, byteorder="big")
    ).rstrip(b"=").decode()


def _build_jwks() -> dict:
    """Build the JSON Web Key Set from the loaded public key."""
    pub_numbers = _public_key.public_key().public_numbers() \
        if hasattr(_public_key, "public_key") \
        else _public_key.public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": _kid,
                "n":   _int_to_base64url(pub_numbers.n),
                "e":   _int_to_base64url(pub_numbers.e),
            }
        ]
    }


def get_jwks() -> dict:
    """Return the cached JWKS dict (safe to serialize directly to JSON)."""
    return _jwks_cache


def get_kid() -> str:
    return _kid


def sign_token(payload: dict) -> str:
    """
    Sign a JWT with the RSA private key (RS256).
    Adds 'kid' header so verifiers can fetch the right key from JWKS.
    """
    if _private_key is None:
        raise RuntimeError("Keys not initialised — call init_keys() first")

    private_pem = _PRIVATE_KEY_PATH.read_bytes().decode()
    return jose_jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": _kid},
    )


def verify_token(token: str) -> dict:
    """
    Verify a JWT using the RSA public key (RS256).
    Any microservice can do this using only the public key / JWKS endpoint.
    """
    if _public_key is None:
        raise RuntimeError("Keys not initialised — call init_keys() first")

    public_pem = _PUBLIC_KEY_PATH.read_bytes().decode()
    return jose_jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
    )
