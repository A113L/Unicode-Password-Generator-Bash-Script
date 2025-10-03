"""
UNICODE Password Utility (Generator & Encrypter/Decrypter)

This script generates cryptographically secure passwords using a vast Unicode character pool.
It offers two modes:
1. Generate: Creates passwords and securely encrypts them to a file using OpenSSL (AES-256-CBC)
   with a user-chosen password. The unencrypted temporary file is automatically deleted.
2. Decrypt: Decrypts an existing password file using the OpenSSL method and the chosen password.

Requires OpenSSL to be installed and accessible in the system PATH.
"""

import string
import secrets
import math
import sys
import subprocess
import os
import getpass
from datetime import datetime

# --- Configuration ---
# Character pool is defined as a standard Python string, which is always Unicode.
UNICODE_POOL = string.ascii_letters + string.digits + string.punctuation
# Greek, Cyrillic, accented Latin, Thai, Devanagari, Japanese, Chinese, Math symbols, Dingbats
UNICODE_POOL += "ąćęłńóśźżĄĆĘŁŃÓŚŹŻäöüßÄÖÜ"
UNICODE_POOL += "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТФХЦЧШЩЪЫЬЭЮЯ"
UNICODE_POOL += "èéêëēėęùúûüūîïíīįìôöòóœøãåáàâæçñ"
UNICODE_POOL += "กขคฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮ"
UNICODE_POOL += "อआइईउऊऋएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह"
UNICODE_POOL += "あいうえおかきくけこさしすせそたちつてとなにぬねのアイウエオカキクケコサシスセソタチツテトナニヌネノ"
UNICODE_POOL += "漢字日本語中文测试字符∞±≠∑∏√∫∂∆πµΩ≈≡≤≥∇¢£¥€₩₪₹₽฿₫₴₦₲"
UNICODE_POOL += "★☆☀☁☂☃☄☠☢☣♠♣♥♦♪♫✔✖✳❄‼"

POOL_SIZE = len(UNICODE_POOL)

# --- Functions ---

def calculate_entropy(length, pool_size):
    """Calculates Shannon Entropy: H = L * log2(N)"""
    if pool_size <= 1:
        return 0.00
    # Use math.log2 for precise base-2 logarithm
    entropy = length * math.log2(pool_size)
    return round(entropy, 2)

def rate_entropy(entropy):
    """Rates password strength based on entropy bits."""
    if entropy < 40:
        return "Very Weak"
    elif entropy < 60:
        return "Weak"
    elif entropy < 80:
        return "Moderate"
    elif entropy < 100:
        return "Strong"
    else:
        return "Very Strong"

def generate_password(length):
    """Generates a secure password using secrets.choice for cryptographic randomness."""
    if length <= 0:
        return ""
    # secrets.choice is the standard, cryptographically secure way to select random elements
    # from a sequence in Python, handling Unicode perfectly.
    return ''.join(secrets.choice(UNICODE_POOL) for _ in range(length))

def run_generator():
    """Logic for generating and encrypting passwords."""
    print("\n--- Unicode Password Generator (Python 3) ---")

    # 1. Get Password Length
    try:
        length = int(input("Enter desired password length (e.g., 20): ") or 20)
        if length < 1:
            print("Error: Invalid length. Using default length of 20.")
            length = 20
    except ValueError:
        print("Error: Invalid length. Using default length of 20.")
        length = 20

    # 2. Get Number of Passwords
    try:
        count = int(input("Enter number of passwords to generate (e.g., 3): ") or 3)
        if count < 1:
            print("Error: Invalid count. Using default count of 3.")
            count = 3
    except ValueError:
        print("Error: Invalid count. Using default count of 3.")
        count = 3

    # 3. Ask for File Save and Encryption
    save_choice = input("Do you want to save the passwords to an *ENCRYPTED* file? (y/n): ").strip().lower()
    save_file = ""
    temp_file = "" # Variable for temporary, unencrypted storage

    if save_choice == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # The final, encrypted file
        save_file = f"passwords_encrypted_{timestamp}.enc"
        # The temporary, unencrypted file (will be deleted after encryption)
        temp_file = f"passwords_temp_{timestamp}.txt"
        
        print(f"Passwords will be saved to temporary file: {temp_file}")
        print(f"Then encrypted to final file: {save_file}")
        
        # Initialize the *temporary* file with a clean header
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write("--- Generated Passwords ---\n\n")
        except IOError:
            print(f"Error: Could not open or write to temporary file {temp_file}.")
            save_file = "" # Disable saving
            temp_file = ""

    # Calculate Entropy
    entropy = calculate_entropy(length, POOL_SIZE)
    strength = rate_entropy(entropy)

    print("\n--- Generation Parameters ---")
    print(f"Character Pool Size: {POOL_SIZE} unique characters")
    print(f"Password Length:       {length} characters")
    print(f"Calculated Entropy:  {entropy} bits")
    print(f"Estimated Strength:  {strength}")
    print("-----------------------------\n")

    generated_passwords = []
    
    for i in range(1, count + 1):
        pwd = generate_password(length)
        generated_passwords.append(pwd)
        
        # Display to terminal
        print(f"#{i}: {pwd}")

    # 4. Save to Temporary File and Encrypt (if requested)
    if temp_file and save_file:
        # --- STEP 4a: Write to Temporary File ---
        try:
            with open(temp_file, 'a', encoding='utf-8') as f:
                for pwd in generated_passwords:
                    f.write(f"{pwd}\n")
                f.write("\n--- End of Passwords ---\n")
            
            print(f"\nSuccessfully saved {count} passwords to temporary file '{temp_file}'.")
            
            # --- STEP 4b: Get Password from User and Encrypt with OpenSSL ---
            
            print("\n--- Starting OpenSSL Encryption ---")
            
            # Use getpass to securely prompt the user for the password
            encryption_key = getpass.getpass("Enter your chosen encryption password (will not be displayed): ").strip()
            
            if not encryption_key:
                print("Error: Encryption password cannot be empty. Cancelling save.")
                raise ValueError("Empty encryption key.")

            # OpenSSL typically asks for the password twice for verification
            print("You will now be prompted to verify the password.")
            
            # OpenSSL command to encrypt: temp -> final. 
            # The '-' tells openssl to read the key from stdin
            openssl_command = [
                'openssl', 'enc', '-aes-256-cbc', 
                '-salt', '-k', '-', 
                '-in', temp_file, 
                '-out', save_file
            ]
            
            # Execute the command, piping the password (twice) to OpenSSL's stdin
            # The password must be followed by a newline (\n) and encoded to bytes.
            subprocess.run(
                openssl_command, 
                input=encryption_key + '\n' + encryption_key + '\n', 
                check=True, 
                capture_output=True, 
                text=True, 
                encoding='utf-8'
            )
            
            print(f"\nEncryption successful! Passwords saved to '{save_file}'.")
            print("To decrypt later, select the Decrypt option when running this script and use the same password.")
            
            # --- STEP 4c: Clean up the Temporary File ---
            # This is the guaranteed automatic deletion of the temporary file upon success
            os.remove(temp_file)
            print(f"Temporary file '{temp_file}' automatically deleted.")
            
        except subprocess.CalledProcessError as e:
            # OpenSSL generally outputs the useful error message to stderr
            error_output = e.stderr or "No specific error output from OpenSSL."
            print(f"\nError: OpenSSL encryption failed. Passwords were only displayed above.")
            print(f"Error details: {error_output}")
            if os.path.exists(temp_file):
                print(f"The temporary file '{temp_file}' still exists and must be SECURELY DELETED.")
        
        except (FileNotFoundError, ValueError) as e:
            print(f"\nError: {'The openssl command was not found.' if isinstance(e, FileNotFoundError) else str(e)}")
            if os.path.exists(temp_file):
                print(f"The temporary file '{temp_file}' still exists and must be SECURELY DELETED.")
            
        except IOError:
            print(f"\nError: Failed to write to temporary file {temp_file}.")
            
    print("\nGenerator finished. Don't forget to secure the generated passwords.")


def decrypt_file():
    """Logic for decrypting an encrypted file using OpenSSL."""
    print("\n--- OpenSSL File Decryption ---")
    
    encrypted_file = input("Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): ").strip()
    
    if not encrypted_file or not os.path.exists(encrypted_file):
        print(f"Decryption cancelled. File '{encrypted_file}' not found or name not provided.")
        return

    # Create an output file name based on the input
    if encrypted_file.endswith(".enc"):
        decrypted_file = encrypted_file[:-4] + "_decrypted.txt"
    else:
        decrypted_file = encrypted_file + "_decrypted.txt"
    
    print(f"The decrypted content will be saved to: {decrypted_file}")
    
    # --- Get Decryption Key from User ---
    decryption_key = getpass.getpass("Enter the decryption password (will not be displayed): ").strip()

    if not decryption_key:
        print("Error: Decryption password cannot be empty. Cancelling decryption.")
        return

    try:
        # OpenSSL command to decrypt: encrypted -> decrypted. 
        # The key is read from stdin using '-k' and '-'.
        openssl_command = [
            'openssl', 'enc', '-aes-256-cbc', 
            '-d', '-salt', '-k', '-', 
            '-in', encrypted_file, 
            '-out', decrypted_file
        ]
        
        # Execute the command, piping the password to OpenSSL's stdin
        # OpenSSL decryption only prompts for the key once.
        subprocess.run(
            openssl_command, 
            input=decryption_key + '\n', 
            check=True, 
            capture_output=True, 
            text=True, 
            encoding='utf-8'
        )

        print(f"\nDecryption successful! Content saved to '{decrypted_file}'.")
        print("WARNING: This decrypted file is now in PLAIN TEXT. Securely delete it when finished.")

    except subprocess.CalledProcessError as e:
        error_output = e.stderr or "No specific error output from OpenSSL."
        print(f"\nError: OpenSSL decryption failed. This is often due to an incorrect password.")
        print(f"Error details: {error_output}")
        if os.path.exists(decrypted_file):
            # Clean up the failed output file
            os.remove(decrypted_file) 
            print(f"Incomplete output file '{decrypted_file}' has been deleted.")
            
    except FileNotFoundError:
        print("\nError: The 'openssl' command was not found.")
        print("Please ensure OpenSSL is installed and available in your system's PATH.")
        
    except IOError:
        print(f"\nError: Could not write to output file {decrypted_file}.")


def main():
    """Main execution function with choice of Generate or Decrypt."""
    
    print("--- Unicode Password Utility (Generate/Decrypt) ---")
    
    choice = input("Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): ").strip().lower()
    
    if choice == 'g':
        run_generator()
    elif choice == 'd':
        decrypt_file()
    else:
        print("Invalid choice. Exiting.")
        
    print("\nHave a great day!")


if __name__ == "__main__":
    main()
