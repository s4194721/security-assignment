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