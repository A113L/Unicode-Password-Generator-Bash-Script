import string
import secrets
import math
import sys
from datetime import datetime

# --- Configuration ---
# Character pool is defined as a standard Python string, which is always Unicode.
UNICODE_POOL = string.ascii_letters + string.digits + string.punctuation
# Greek, Cyrillic, accented Latin, Thai, Devanagari, Japanese, Chinese, Math symbols, Dingbats
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

def main():
    """Main execution function."""
    
    print("--- Unicode Password Generator (Python 3) ---")

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

    # 3. Ask for File Save
    save_choice = input("Do you want to save the passwords to a file? (y/n): ").strip().lower()
    save_file = ""
    
    if save_choice == 'y':
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_file = f"passwords_{timestamp}.txt"
        print(f"Saving passwords to file: {save_file}")
        
        # Initialize the file with a clean header
        try:
            with open(save_file, 'w', encoding='utf-8') as f:
                f.write("--- Generated Passwords ---\n\n")
        except IOError:
            print(f"Error: Could not open or write to file {save_file}.")
            save_file = "" # Disable saving

    # Calculate Entropy
    entropy = calculate_entropy(length, POOL_SIZE)
    strength = rate_entropy(entropy)

    print("\n--- Generation Parameters ---")
    print(f"Character Pool Size: {POOL_SIZE} unique characters")
    print(f"Password Length:     {length} characters")
    print(f"Calculated Entropy:  {entropy} bits")
    print(f"Estimated Strength:  {strength}")
    print("-----------------------------\n")

    generated_passwords = []
    
    for i in range(1, count + 1):
        pwd = generate_password(length)
        generated_passwords.append(pwd)
        
        # Display to terminal
        print(f"#{i}: {pwd}")

    # 4. Save to File (if requested)
    if save_file:
        try:
            with open(save_file, 'a', encoding='utf-8') as f:
                for pwd in generated_passwords:
                    f.write(f"{pwd}\n")
                
                f.write("\n--- End of Passwords ---\n")
            
            print(f"\nSuccessfully saved {count} passwords to '{save_file}'.")
            print("Remember to secure this file.")

        except IOError:
            print(f"\nError: Failed to append passwords to file {save_file}. Passwords were only displayed above.")
            
    print("\nGenerator finished. Have a great day!")


if __name__ == "__main__":
    main()
