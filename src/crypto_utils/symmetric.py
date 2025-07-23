from cryptography.fernet import Fernet


def encrypt_message(key: bytes, message: str) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode())


def decrypt_message(key: bytes, token: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode()
