import hashlib
import os


def hash_password(password: str) -> [bytes, bytes]:
    salt = os.urandom(0x20)
    return [hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000), salt]


def verify_password(password_plain: str, password_hash: bytes, salt: bytes, ):
    candidate_hash = hashlib.pbkdf2_hmac("sha256", password_plain.encode("utf-8"), salt, 100_000)

    return candidate_hash == password_hash


if __name__ == "__main__":
    pass
