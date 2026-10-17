from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from pathlib import Path
import secrets
import math

BASE = Path(__file__).resolve().parent

#Prompt for taking user input, followed the structure provied in Cipher.exe
print("Question 7.3 - Improved Encryption")

first_name = input("Enter first name: ").strip()
last_name = input("Enter last name: ").strip()

p = int(input("Enter prime 1 (>1000000): "))
q = int(input("Enter prime 2 (>1000000): "))

plaintext = input("Enter plaintext (letters only): ").strip()


#Checking the name, minimum prime values, and plaintext format
#Verifying p and q as prime
if not first_name.isascii() or not first_name.isalpha():
    raise ValueError("First name must contain English letters only.")

if not last_name.isascii() or not last_name.isalpha():
    raise ValueError("Last name must contain English letters only.")

if p <= 1000000 or q <= 1000000:
    raise ValueError("Both primes must be greater than 1,000,000.")

if p == q:
    raise ValueError("The two primes must be different.")

if (
    len(plaintext) < 3
    or not plaintext.isascii()
    or not plaintext.isalpha()
):
    raise ValueError("Plaintext must contain at least 3 English letters.")

# Check whether a number is prime
def is_prime(n):
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2

    return True


# Verify the two input numbers
if not is_prime(p):
    raise ValueError("Prime 1 is not a prime number.")

if not is_prime(q):
    raise ValueError("Prime 2 is not a prime number.")

print("\nInput validation successful!")
print("Both numbers are prime.")


# Step 7: Generate RSA keys
e = 65537

# Calculate RSA modulus
n = p * q

# Calculate Euler's totient
phi = (p - 1) * (q - 1)

# Check whether e and phi are coprime
if math.gcd(e, phi) != 1:
    raise ValueError("Invalid primes for the selected public exponent.")

# Calculate private exponent
d = pow(e, -1, phi)

# Store RSA keys
public_key = (e, n)
private_key = (d, n)

print("\nRSA Key Generation:")
print("Public Key:", public_key)
print("Private Key:", private_key)

# Verify RSA key relationship
print("Key Verification:", (e * d) % phi == 1)


# Step 11: Generate secure RSA keys
secure_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

secure_public_key = secure_private_key.public_key()

print("\nSecure RSA key pair generated successfully!")
print("RSA key size:", secure_public_key.key_size, "bits")


# Step 12: Encrypt plaintext using RSA-OAEP

message_bytes = plaintext.encode("utf-8")

ciphertext = secure_public_key.encrypt(
    message_bytes,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nOriginal Plaintext:", plaintext)
print("Encrypted Ciphertext (hex):")
print(ciphertext.hex())


# Step 13: Decrypt ciphertext using private key

decrypted_bytes = secure_private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=None
    )
)

decrypted_message = decrypted_bytes.decode("utf-8")

print("\nDecrypted Plaintext:", decrypted_message)

if decrypted_message == plaintext:
    print("SUCCESS: Secure encryption and decryption worked!")
else:
    print("FAILED: Decrypted message does not match!")
