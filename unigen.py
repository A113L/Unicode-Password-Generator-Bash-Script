"""
UNICODE Password Utility (Generator & Encrypter/Decrypter)

This script generates cryptographically secure passwords using a vast Unicode character pool.
It offers two modes:
1. Generate: Creates passwords and securely encrypts them to a file using OpenSSL (AES-256-CBC)
   with a user-chosen password. The unencrypted temporary file is SECURELY DELETED using shred.
2. Decrypt: Decrypts an existing password file. After viewing/editing, the plain-text file
   is re-encrypted and then SECURELY DELETED using shred.

Requires OpenSSL and preferably 'shred' (Linux/macOS) to be installed and accessible in the system PATH.
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
UNICODE_POOL = string.ascii_letters + string.digits + string.punctuation
UNICODE_POOL += "ąćęłńóśźżĄĆĘŁŃÓŚŹŻäöüßÄÖÜ"
UNICODE_POOL += "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТФХЦЧШЩЪЫЬЭЮЯ"
UNICODE_POOL += "èéêëēėęùúûüūîïíīįìôöòóœøãåáàâæçñ"
UNICODE_POOL += "กขคฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮ"
UNICODE_POOL += "अआइईउऊऋएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह"
UNICODE_POOL += "あいうえおかきくけこさしすせそたちつてとなにぬねのアイウエオカキクケコサシスセソタチツテトナニヌネノ"
UNICODE_POOL += "漢字日本語中文测试字符∞±≠∑∏√∫∂∆πµΩ≈≡≤≥∇¢£¥€₩₪₹₽฿₫₴₦₲"
UNICODE_POOL += "★☆☀☁☂☃☄☠☢☣♠♣♥♦♪♫✔✖✳❄‼"

POOL_SIZE = len(UNICODE_POOL)

# --- Functions ---

def calculate_entropy(length, pool_size):
    """Calculates Shannon Entropy: H = L * log2(N)"""
    if pool_size <= 1:
        return 0.00
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
    return ''.join(secrets.choice(UNICODE_POOL) for _ in range(length))

def secure_delete(filepath):
    """
    Securely deletes a file using the 'shred' utility (overwrites data).
    Falls back to os.remove() if 'shred' is unavailable.
    """
    if not os.path.exists(filepath):
        return

    print(f"\nAttempting to securely delete: {filepath}")
    
    try:
        # Use shred: -n 3 (3 passes), -z (final overwrite with zeros), -u (truncate and remove)
        shred_command = ['shred', '-n', '3', '-z', '-u', filepath]
        
        # Suppress output, run the command
        subprocess.run(shred_command, check=True, capture_output=True, text=True)
        print("✅ Secure deletion via 'shred' successful.")
        
    except FileNotFoundError:
        # shred not found, fall back to standard deletion
        print("⚠️ 'shred' command not found. Falling back to standard os.remove().")
        try:
            os.remove(filepath)
            print(f"Standard deletion of '{filepath}' complete.")
        except Exception as e_inner:
            print(f"❌ Fatal Error: Could not delete file even with os.remove. Manual deletion required.")
            print(f"The vulnerable file '{filepath}' remains on disk! Error: {e_inner}")
    except subprocess.CalledProcessError as e:
        # shred failed for other reason (e.g., permissions)
        print(f"❌ 'shred' failed (Error: {e.stderr.strip()}). Falling back to standard os.remove().")
        try:
            os.remove(filepath)
            print(f"Standard deletion of '{filepath}' complete.")
        except Exception as e_inner:
            print(f"❌ Fatal Error: Could not delete file even with os.remove. Manual deletion required.")
            print(f"The vulnerable file '{filepath}' remains on disk! Error: {e_inner}")

def encrypt_file(input_file, output_file, key):
    """
    Encrypts an input file to an output file using OpenSSL.
    Requires the encryption key as input.
    """
    print(f"\n--- Starting OpenSSL Encryption: {input_file} -> {output_file} ---")
    
    # OpenSSL command to encrypt: input -> output
    openssl_command = [
        'openssl', 'enc', '-aes-256-cbc', 
        '-salt', '-k', '-', 
        '-in', input_file, 
        '-out', output_file
    ]
    
    # Execute the command, piping the password (twice) to OpenSSL's stdin
    subprocess.run(
        openssl_command, 
        input=key + '\n' + key + '\n', 
        check=True, 
        capture_output=True, 
        text=True, 
        encoding='utf-8'
    )
    
    print(f"Encryption successful! Content saved to '{output_file}'.")

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
    temp_file = "" 

    if save_choice == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_file = f"passwords_encrypted_{timestamp}.enc"
        temp_file = f"passwords_temp_{timestamp}.txt"
        
        print(f"Passwords will be saved to temporary file: {temp_file}")
        print(f"Then encrypted to final file: {save_file}")
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write("--- Generated Passwords ---\n\n")
        except IOError:
            print(f"Error: Could not open or write to temporary file {temp_file}.")
            save_file = "" 
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
        print(f"#{i}: {pwd}")

    # 4. Save to Temporary File and Encrypt (if requested)
    if temp_file and save_file:
        try:
            # 4a: Write to Temporary File
            with open(temp_file, 'a', encoding='utf-8') as f:
                for pwd in generated_passwords:
                    f.write(f"{pwd}\n")
                f.write("\n--- End of Passwords ---\n")
            
            print(f"\nSuccessfully saved {count} passwords to temporary file '{temp_file}'.")
            
            # 4b: Get Password from User
            encryption_key = getpass.getpass("Enter your chosen encryption password (will not be displayed): ").strip()
            if not encryption_key:
                print("Error: Encryption password cannot be empty. Cancelling save.")
                raise ValueError("Empty encryption key.")

            # 4c: Encrypt
            encrypt_file(temp_file, save_file, encryption_key)
            
            # 4d: Clean up the Temporary File
            secure_delete(temp_file)
            
        except subprocess.CalledProcessError as e:
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

# ---------------------------------------------------------------------

def decrypt_file():
    """Logic for decrypting an encrypted file and offering re-encryption."""
    print("\n--- OpenSSL File Decryption ---")
    
    encrypted_file = input("Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): ").strip()
    
    if not encrypted_file or not os.path.exists(encrypted_file):
        print(f"Decryption cancelled. File '{encrypted_file}' not found or name not provided.")
        return

    if encrypted_file.endswith(".enc"):
        decrypted_file = encrypted_file[:-4] + "_decrypted.txt"
    else:
        decrypted_file = encrypted_file + "_decrypted.txt"
    
    print(f"The decrypted content will be saved to: {decrypted_file}")
    
    decryption_key = getpass.getpass("Enter the decryption password (will not be displayed): ").strip()

    if not decryption_key:
        print("Error: Decryption password cannot be empty. Cancelling decryption.")
        return

    try:
        # Execute decryption command
        openssl_command = [
            'openssl', 'enc', '-aes-256-cbc', 
            '-d', '-salt', '-k', '-', 
            '-in', encrypted_file, 
            '-out', decrypted_file
        ]
        
        subprocess.run(
            openssl_command, 
            input=decryption_key + '\n', 
            check=True, 
            capture_output=True, 
            text=True, 
            encoding='utf-8'
        )

        print(f"\nDecryption successful! Content saved to '{decrypted_file}'.")
        
        # --- Display Content ---
        print("\n--- Decrypted Content ---")
        try:
            with open(decrypted_file, 'r', encoding='utf-8') as f:
                print(f.read())
        except IOError:
            print(f"Error: Could not read content from '{decrypted_file}'.")
        print("---------------------------\n")

        print("WARNING: The file listed above is currently saved as PLAIN TEXT on disk.")
        print("You can now open and edit the file if needed.")
        
        # --- Offer Re-encryption ---
        re_encrypt_choice = input(f"Do you want to re-encrypt '{decrypted_file}' now? (y/n): ").strip().lower()
        
        if re_encrypt_choice == 'y':
            print(f"Re-encrypting the file back to '{encrypted_file}'.")
            
            encrypt_file(decrypted_file, encrypted_file, decryption_key)
            
            # Clean up the decrypted file SECURELY
            secure_delete(decrypted_file) 
            print("\nRe-encryption complete. Plain-text file automatically deleted.")
            
        else:
            print(f"\nWARNING: The file '{decrypted_file}' is currently in PLAIN TEXT.")
            print("Remember to SECURELY delete or re-encrypt it when finished editing.")


    except subprocess.CalledProcessError as e:
        error_output = e.stderr or "No specific error output from OpenSSL."
        print(f"\nError: OpenSSL decryption failed. This is often due to an incorrect password.")
        print(f"Error details: {error_output}")
        if os.path.exists(decrypted_file):
            # Clean up the failed output file (standard delete if shred not found)
            secure_delete(decrypted_file)
            print(f"Incomplete output file has been deleted.")
            
    except FileNotFoundError:
        print("\nError: The 'openssl' command was not found.")
        print("Please ensure OpenSSL is installed and available in your system's PATH.")
        
    except IOError:
        print(f"\nError: Could not write to output file {decrypted_file}.")

# ---------------------------------------------------------------------

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
