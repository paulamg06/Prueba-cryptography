from crypto_utils.key_manager import (
    generate_rsa_key_pair,
    generate_symmetric_key,
    serialize_private_key,
    serialize_public_key
)
from crypto_utils.asymmetric import sign_message, verify_signature
from crypto_utils.symmetric import encrypt_message, decrypt_message

def main():
    # Mensaje
    message = "Este es un mensaje secreto."

    # --- Criptografía asimétrica ---
    print("\n🛡️  Criptografía Asimétrica (Firma Digital)")
    private_key, public_key = generate_rsa_key_pair()

    signature = sign_message(private_key, message.encode())
    print("🔏 Firma generada.")

    is_valid = verify_signature(public_key, message.encode(), signature)
    print("✅ Firma válida:", is_valid)

    # --- Criptografía simétrica ---
    print("\n🔐 Criptografía Simétrica (AES - Fernet)")
    sym_key = generate_symmetric_key()

    ciphertext = encrypt_message(sym_key, message)
    print("🧪 Mensaje cifrado:", ciphertext)

    decrypted = decrypt_message(sym_key, ciphertext)
    print("📜 Mensaje descifrado:", decrypted)


if __name__ == "__main__":
    main()
