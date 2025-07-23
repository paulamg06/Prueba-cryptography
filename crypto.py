from cryptography.fernet import Fernet

# 1. Generar una clave y guardarla en un archivo
def generate_key(filepath="secret.key"):
    key = Fernet.generate_key()
    with open(filepath, "wb") as key_file:
        key_file.write(key)
    print(f"Clave generada y guardada en {filepath}")
    return key

# 2. Cargar una clave desde un archivo
def load_key(filepath="secret.key"):
    with open(filepath, "rb") as key_file:
        key = key_file.read()
    return key

# 3. Encriptar un mensaje
def encrypt_message(message: str, key: bytes) -> bytes:
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    return encrypted

# 4. Desencriptar un mensaje
def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_message)
    return decrypted.decode()

# Main para pruebas
if __name__ == "__main__":
    key = generate_key()
    message = "Este es un mensaje secreto."

    encrypted = encrypt_message(message, key)
    print("Mensaje encriptado:", encrypted)

    decrypted = decrypt_message(encrypted, key)
    print("Mensaje desencriptado:", decrypted)
