# Unicode-Password-Generator-Python-Script

This is a secure, high-entropy password generator written in Python 3 that utilizes a massive Unicode character pool.

It prompts the user for the desired password length and count, then generates cryptographically secure passwords using Python's secrets module. It also calculates the Shannon Entropy to provide a numerical measure of password strength and offers the option to safely save the generated passwords to a timestamped UTF-8 encoded file.

```
# python3 unigen.py
--- Unicode Password Utility (Generate/Decrypt) ---
Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): g

--- Unicode Password Generator (Python 3) ---
Enter desired password length (e.g., 20): 16
Enter number of passwords to generate (e.g., 3): 10
Do you want to save the passwords to an *ENCRYPTED* file? (y/n): y
Passwords will be saved to temporary file: passwords_temp_20251003_041112.txt
Then encrypted to final file: passwords_encrypted_20251003_041112.enc

--- Generation Parameters ---
Character Pool Size: 414 unique characters
Password Length:       16 characters
Calculated Entropy:  139.1 bits
Estimated Strength:  Very Strong
-----------------------------

#1: ГŹ♥СケつआøテêナÖ∂♠<中
#2: ษฏอWचМµ`q)}∫Нイฝx
#3: औЧई₪ถภとóछQZछす`文♣
#4: œЬセクถ∏èœФЩठ3うйあฝ
#5: कฏดญ√ąśКおサп₲į√ด字
#6: せอВп&≥コЗ^µлa]♫_ы
#7: Żいłग*F∆:tฒฦJШผхड
#8: コБs♠Z)dОИウ(∑òスฦ文
#9: х☂けईアø₦☄ह<एhēцล9
#10: afにढखïシฟय符कЯ>#ध\

Successfully saved 10 passwords to temporary file 'passwords_temp_20251003_041112.txt'.

--- Starting OpenSSL Encryption ---
Enter your chosen encryption password (will not be displayed): 
You will now be prompted to verify the password.

Encryption successful! Passwords saved to 'passwords_encrypted_20251003_041112.enc'.
To decrypt later, select the Decrypt option when running this script and use the same password.
Temporary file 'passwords_temp_20251003_041112.txt' automatically deleted.

Generator finished. Don't forget to secure the generated passwords.

Have a great day!
# python3 unigen.py
--- Unicode Password Utility (Generate/Decrypt) ---
Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): d

--- OpenSSL File Decryption ---
Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): passwords_encrypted_20251003_041112.enc
The decrypted content will be saved to: passwords_encrypted_20251003_041112_decrypted.txt
Enter the decryption password (will not be displayed): 

Decryption successful! Content saved to 'passwords_encrypted_20251003_041112_decrypted.txt'.
WARNING: This decrypted file is now in PLAIN TEXT. Securely delete it when finished.

Have a great day!
# cat passwords_encrypted_20251003_041112_decrypted.txt
--- Generated Passwords ---

ГŹ♥СケつआøテêナÖ∂♠<中
ษฏอWचМµ`q)}∫Нイฝx
औЧई₪ถภとóछQZछす`文♣
œЬセクถ∏èœФЩठ3うйあฝ
कฏดญ√ąśКおサп₲į√ด字
せอВп&≥コЗ^µлa]♫_ы
Żいłग*F∆:tฒฦJШผхड
コБs♠Z)dОИウ(∑òスฦ文
х☂けईアø₦☄ह<एhēцล9
afにढखïシฟय符कЯ>#ध\

--- End of Passwords ---
# 

```

How the File Password is Handled in This Script?

The file password is not stored in the script in any form. The script is designed to minimize security risks.

Here is how it works in the context of file encryption and decryption:

1. **Handling (or Non-Storage) of the Password**
User Input: The script uses the getpass module (specifically, the getpass.getpass() function) to load the password directly from the console. This ensures the password is typed in hidden mode and is never displayed on the screen or saved in logs or command history.

Transfer to OpenSSL: The entered password is immediately piped (transferred) to the OpenSSL process using the subprocess module. The password is sent to OpenSSL as standard input (input=encryption_key + '\n'), which OpenSSL reads from stdin due to the use of the -k - arguments in the command.

Lack of Persistence: After the subprocess.run() command is executed, the password ceases to exist in the script's memory.

2. **How OpenSSL Uses the Password**
OpenSSL uses the password to:

Derive the Encryption Key: The password is mixed with a unique, random value called a salt, and is then transformed into the actual encryption key that locks the data in the file.

Encrypt the File: The actual data in the file (.enc) is encrypted using the AES-256-CBC algorithm.

Salt Storage: The salt is saved inside the encrypted file, but the password itself is not stored. The salt is necessary to correctly re-derive the encryption key during decryption.

In summary: The password exists in the computer's memory for only a fraction of a second while the user types it and it is piped to OpenSSL, and then it is cleared. The script deliberately does not store the password.
