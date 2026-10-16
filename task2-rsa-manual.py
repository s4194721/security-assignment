import os
import secrets
import math

BASE = os.path.dirname(os.path.abspath(__file__))

message = "4194721"


#Function for finding prime number
#This process uses 50 rounds to cross check whether the choosen number is actually prime or not
def is_prime(n, rounds=50):
    if n < 2:
        return False
    #List of prime numbers till 50
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    #Checking prime number
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Miller-Rabin primality test(algorithm used to determine a prime number)
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for i in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for j in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


#Generating a large prime number for p and q
#This function keeps generating random numbers until it finds one
def generate_prime(bits=1024): 
    while True:
        number = secrets.randbits(bits) #Generates a random integer using up to 1024 bits
        number |= (1 << (bits - 1)) #Checks bit
        number |= 1 #Odd number

        if is_prime(number):
            return number


#Generating RSA public and private keys
def generate_keys():
    e = 65537

    while True:
        p = generate_prime()
        q = generate_prime()

        if p == q:
            continue

        n = p * q
        phi_n = (p - 1) * (q - 1)

        if math.gcd(e, phi_n) == 1:
            break

    # Modular inverse
    d = pow(e, -1, phi_n)

    return (e, n), (d, n), p, q, phi_n


#Encryption
def encrypt(message, public_key):
    e, n = public_key

    message_bytes = message.encode("utf-8")
    message_int = int.from_bytes(message_bytes, "big")

    if message_int >= n:
        raise ValueError("Message is too large for RSA modulus")

    ciphertext = pow(message_int, e, n)
    return ciphertext


#Decryption
def decrypt(ciphertext, private_key):
    d, n = private_key

    message_int = pow(ciphertext, d, n)

    byte_length = (message_int.bit_length() + 7) // 8
    message_bytes = message_int.to_bytes(byte_length, "big")

    return message_bytes.decode("utf-8")


#Main program
print("Question 2 - MANUAL RSA ENCRYPTION")

public_key, private_key, p, q, phi_n = generate_keys()

print("Generated Prime Numbers:")
print("p =", p)
print("q =", q)

print("RSA Parameters:")
print("n =", public_key[1])
print("phi(n) =", phi_n)

print("Public Key (e, n):")
print(public_key)

print("Private Key (d, n):")
print(private_key)

print("Plaintext:", message)

ciphertext = encrypt(message, public_key)
print("Ciphertext:")
print(ciphertext)

decrypted_message = decrypt(ciphertext, private_key)
print("Decrypted Message:")
print(decrypted_message)


if message == decrypted_message:
    print("RSA encryption and decryption was successful")
else:
    print("RSA encryption and decryption failed")
