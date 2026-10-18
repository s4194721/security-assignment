from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

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

# Miller-Rabin primality test
def is_prime(n, rounds=40):
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    # Express n - 1 as d * 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Perform Miller-Rabin testing
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


# Verify the two input numbers
if not is_prime(p):
    raise ValueError("Prime 1 is not a prime number.")

if not is_prime(q):
    raise ValueError("Prime 2 is not a prime number.")

print("Input validation successful!")
print("Both numbers are prime.")



# Step 11: Generate secure RSA keys
secure_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

secure_public_key = secure_private_key.public_key()

# Save the secure RSA private key for later decryption
private_key_path = BASE / "rsa_private.pem"

private_key_bytes = secure_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

private_key_path.write_bytes(private_key_bytes)

print("Private key saved to:", private_key_path)


print("Secure RSA key pair generated successfully!")
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


# Step 15: Save the RSA public key and ciphertext

# Extract public key numbers
public_numbers = secure_public_key.public_numbers()

secure_e = public_numbers.e
secure_n = public_numbers.n

# Convert encrypted bytes into an integer
ciphertext_int = int.from_bytes(ciphertext, "big")

# Generate initials from the name
initials = (
    first_name[0] + last_name[0]
).upper()

# Save the public key
key_path = BASE / "key.txt"

key_path.write_text(
    f"({secure_e}, {secure_n})",
    encoding="utf-8"
)

# Save ciphertext and initials
cipher_path = BASE / "cipher.txt"

cipher_path.write_text(
    f"{ciphertext_int}\n{initials}",
    encoding="utf-8"
)

print("\nFiles generated successfully!")
print("Public key saved to:", key_path)
print("Ciphertext saved to:", cipher_path)
print("Initials:", initials)
