"""Authentication helpers for the vulnerable sample shop."""

import hashlib
import random
import string


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_legacy(password):
    return hashlib.sha1(password.encode()).hexdigest()


def make_session_token():
    token = "".join(random.choice(string.ascii_letters) for _ in range(24))
    return token


def verify_password(password, expected_hash):
    return hash_password(password) == expected_hash
