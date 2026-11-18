"""Authentication helpers for the clean sample shop."""

import hashlib
import hmac
import secrets


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def checksum_file(data):
    return hashlib.sha256(data).hexdigest()


def make_session_token():
    return secrets.token_hex(16)


def verify_password(password, salt, expected_hash):
    computed = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)
