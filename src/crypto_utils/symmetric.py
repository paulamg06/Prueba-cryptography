from cryptography.fernet import Fernet


def encrypt_message(key: bytes, message: str) -> bytes:
    return Fernet(key).encrypt(message.encode())


def decrypt_message(key: bytes, token: bytes) -> str:
    return Fernet(key).decrypt(token).decode()
