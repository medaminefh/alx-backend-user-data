#!/usr/bin/env python3
"""
Encrypt Password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hahed_password: bytes, password: str) -> bool:
    """Checks if a hashed password is valid"""
    return bcrypt.checkpw(password.encode('utf-8'), hahed_password)
