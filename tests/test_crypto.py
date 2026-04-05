"""
test_crypto.py — Unit tests for RS256 key management and JWKS.

Tests:
  1. Keys initialise without error
  2. Signed token can be verified with the same key
  3. Tampered token fails verification
  4. JWKS response has correct structure
  5. Token signed with wrong key fails verification
  6. JWKS kid matches token header kid
"""

import pytest
import uuid
from jose import jwt as jose_jwt, JWTError
from datetime import datetime, timezone, timedelta
import crypto


def _make_payload() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "sub":  str(uuid.uuid4()),
        "type": "access",
        "iat":  now,
        "exp":  now + timedelta(minutes=15),
    }


class TestKeyInit:
    def test_keys_initialized(self):
        """Keys should be loaded (init_keys called in conftest)."""
        assert crypto._private_key is not None
        assert crypto._public_key  is not None
        assert crypto._kid         != ""

    def test_kid_is_uuid(self):
        """KID should be a valid UUID string."""
        uuid.UUID(crypto._kid)   # raises ValueError if not valid


class TestSignAndVerify:
    def test_sign_and_verify(self):
        """Token signed with private key should verify with public key."""
        payload  = _make_payload()
        token    = crypto.sign_token(payload)
        verified = crypto.verify_token(token)
        assert verified["sub"] == payload["sub"]

    def test_tampered_token_rejected(self):
        """Changing any character in the token should fail verification."""
        token = crypto.sign_token(_make_payload())
        # Flip one character in the signature (last segment)
        parts = token.split(".")
        sig   = list(parts[2])
        sig[0] = "X" if sig[0] != "X" else "Y"
        bad_token = ".".join(parts[:2] + ["".join(sig)])
        with pytest.raises(Exception):  # JWTError or similar
            crypto.verify_token(bad_token)

    def test_expired_token_rejected(self):
        """An already-expired token should fail verification."""
        payload = {
            "sub":  str(uuid.uuid4()),
            "type": "access",
            "iat":  datetime(2020, 1, 1, tzinfo=timezone.utc),
            "exp":  datetime(2020, 1, 1, tzinfo=timezone.utc),  # expired
        }
        token = crypto.sign_token(payload)
        with pytest.raises(Exception):
            crypto.verify_token(token)

    def test_wrong_key_rejected(self, tmp_path):
        """Token signed with a different private key should not verify."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        # Generate a second, independent keypair
        other_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        other_pem = other_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        # Sign with the other key
        payload = _make_payload()
        other_token = jose_jwt.encode(payload, other_pem, algorithm="RS256")

        # Verify with our key — should fail
        with pytest.raises(Exception):
            crypto.verify_token(other_token)


class TestJWKS:
    def test_jwks_structure(self):
        """JWKS must conform to RFC 7517."""
        jwks = crypto.get_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key   # modulus
        assert "e" in key   # exponent
        assert "kid" in key

    def test_jwks_kid_matches_token(self):
        """The kid in the JWKS must match the kid in token headers."""
        token = crypto.sign_token(_make_payload())
        headers = jose_jwt.get_unverified_header(token)
        jwks_kid = crypto.get_jwks()["keys"][0]["kid"]
        assert headers["kid"] == jwks_kid
