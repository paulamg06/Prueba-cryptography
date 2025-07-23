from key_manager import generate_keys, save_private_key, save_public_key
from crypto_utils import encrypt, decrypt, sign, verify

def main():
    private_key, public_key = generate_keys()

    message = b"Hello, this is a secret message."
    print("Original:", message)

    # Encryption / Decryption
    encrypted = encrypt(public_key, message)
    print("Encrypted:", encrypted)

    decrypted = decrypt(private_key, encrypted)
    print("Decrypted:", decrypted)

    # Signing / Verifying
    signature = sign(private_key, message)
    print("Signature:", signature)

    is_valid = verify(public_key, message, signature)
    print("Signature valid?", is_valid)

if __name__ == "__main__":
    main()
