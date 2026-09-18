"""RFC 6238 TOTP codes, so the server can pass Dougs' authenticator-app MFA unattended."""

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, urlparse


def parse_secret(value: str) -> str:
    """Accept either the base32 secret or the full ``otpauth://`` URI Dougs shows at setup."""
    value = value.strip()
    if value.startswith("otpauth://"):
        secrets = parse_qs(urlparse(value).query).get("secret")
        if not secrets:
            raise ValueError("otpauth URI has no secret parameter")
        value = secrets[0]
    return value.replace(" ", "").upper()


def totp(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Current code for a base32 secret (SHA-1, 30 s, 6 digits: the authenticator defaults)."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)
