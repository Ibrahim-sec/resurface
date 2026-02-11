#!/usr/bin/env python3
"""
TOTP Generator for 2FA Authentication Testing
Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)
"""
import hmac
import hashlib
import struct
import time
import base64
import re
from typing import Tuple


def base32_decode(secret: str) -> bytes:
    """Decode base32-encoded TOTP secret."""
    # Normalize: uppercase, remove spaces
    secret = secret.upper().replace(" ", "")
    # Add padding if needed
    padding = 8 - (len(secret) % 8)
    if padding != 8:
        secret += "=" * padding
    return base64.b32decode(secret)


def generate_hotp(secret: str, counter: int, digits: int = 6) -> str:
    """Generate HOTP code (RFC 4226)."""
    key = base32_decode(secret)
    
    # Convert counter to 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)
    
    # Generate HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    
    # Generate digits
    otp = str(code % (10 ** digits)).zfill(digits)
    return otp


def generate_totp(secret: str, time_step: int = 30, digits: int = 6) -> str:
    """Generate TOTP code (RFC 6238)."""
    current_time = int(time.time())
    counter = current_time // time_step
    return generate_hotp(secret, counter, digits)


def get_totp_with_expiry(secret: str, time_step: int = 30) -> Tuple[str, int]:
    """Generate TOTP code and return seconds until expiration."""
    code = generate_totp(secret, time_step)
    current_time = int(time.time())
    expires_in = time_step - (current_time % time_step)
    return code, expires_in


def validate_totp_secret(secret: str) -> bool:
    """Validate that secret is valid base32."""
    pattern = r'^[A-Z2-7]+$'
    clean_secret = secret.upper().replace(" ", "")
    return bool(re.match(pattern, clean_secret))


# CLI usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python totp.py <base32_secret>")
        sys.exit(1)
    
    secret = sys.argv[1]
    if not validate_totp_secret(secret):
        print("Error: Invalid base32 secret")
        sys.exit(1)
    
    code, expires = get_totp_with_expiry(secret)
    print(f"TOTP: {code} (expires in {expires}s)")
