from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(__file__).resolve().parent

#Generating the RSA private and public keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

(BASE / "rsa_private.pem").write_bytes(private_pem)
(BASE / "rsa_public.pem").write_bytes(public_pem)

print("RSA Private Key:")
print(private_pem.decode())

print("RSA Public Key:")
print(public_pem.decode())


plaintext = (BASE / "task2.txt").read_bytes()

print("Original File Content:")
print(plaintext.decode("utf-8"))

#Generating a random 256-bit AES key
aes_key = AESGCM.generate_key(bit_length=256)

#Generating a random 12-byte nonce
nonce = secrets.token_bytes(12)

#Encrypting using AES-GCM
aes = AESGCM(aes_key)

ciphertext = aes.encrypt(nonce, plaintext, None)

(BASE / "task2.encrypted").write_bytes(nonce + ciphertext)

print("\nAES Key (hex):", aes_key.hex())
print("Encrypted File (hex):", ciphertext.hex())

# Encrypting using RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

(BASE / "aes_key.encrypted").write_bytes(encrypted_aes_key)

print("\nRSA Encrypted AES Key (hex):")
print(encrypted_aes_key.hex())

#Load receiver's RSA private key
loaded_private_key = serialization.load_pem_private_key(
    (BASE / "rsa_private.pem").read_bytes(),
    password=None
)

#Recover AES key using RSA private key
recovered_aes_key = loaded_private_key.decrypt(
    (BASE / "aes_key.encrypted").read_bytes(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nRecovered AES Key (hex):")
print(recovered_aes_key.hex())


encrypted_data = (BASE / "task2.encrypted").read_bytes()

#First 12 bytes
received_nonce = encrypted_data[:12]
received_ciphertext = encrypted_data[12:]

#Decryption
decrypted_data = AESGCM(recovered_aes_key).decrypt(
    received_nonce,
    received_ciphertext,
    None
)


(BASE / "task2_decrypted.txt").write_bytes(decrypted_data)

print("Decrypted File Content:")
print(decrypted_data.decode("utf-8"))


if plaintext == decrypted_data and aes_key == recovered_aes_key:
    print("SUCCESS: Hybrid encryption and decryption completed!")
else:
    print("FAILED: Decrypted data does not match!")