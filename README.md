# Unicode-Password-Generator-Python-Script

This is a secure, high-entropy password generator written in Python 3 that utilizes a massive Unicode character pool.

It prompts the user for the desired password length and count, then generates cryptographically secure passwords using Python's secrets module. It also calculates the Shannon Entropy to provide a numerical measure of password strength and offers the option to safely save the generated passwords to a timestamped UTF-8 encoded file. Your cheap console Keepass.

```
$ python3 unigen.py
--- Unicode Password Utility (Generate/Decrypt) ---
Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): g

--- Unicode Password Generator (Python 3) ---
Enter desired password length (e.g., 20): 16
Enter number of passwords to generate (e.g., 3): 5
Do you want to save the passwords to an *ENCRYPTED* file? (y/n): y
Passwords will be saved to temporary file: passwords_temp_20251003_045311.txt
Then encrypted to final file: passwords_encrypted_20251003_045311.enc

--- Generation Parameters ---
Character Pool Size: 414 unique characters
Password Length:       16 characters
Calculated Entropy:  139.1 bits
Estimated Strength:  Very Strong
-----------------------------

#1: гvAПñj☢符нЯ¢ญęचbО
#2: नYW>£पO中qыशã₴ष€ऊ
#3: öà語щฬвuテ☆ภฒó£hधù
#4: ป฿œéएKūटรप`ъ2I-Ω
#5: ☢çअध☀īउСn76ธыо3シ

Successfully saved 5 passwords to temporary file 'passwords_temp_20251003_045311.txt'.
Enter your chosen encryption password (will not be displayed): 

--- Starting OpenSSL Encryption: passwords_temp_20251003_045311.txt -> passwords_encrypted_20251003_045311.enc ---
Encryption successful! Content saved to 'passwords_encrypted_20251003_045311.enc'.

Attempting to securely delete: passwords_temp_20251003_045311.txt
✅ Secure deletion via 'shred' successful.

Generator finished. Don't forget to secure the generated passwords.

Have a great day!
$ python3 unigen.py
--- Unicode Password Utility (Generate/Decrypt) ---
Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): d

--- OpenSSL File Decryption ---
Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): passwords_encrypted_20251003_045311.enc
The decrypted content will be saved to: passwords_encrypted_20251003_045311_decrypted.txt
Enter the decryption password (will not be displayed): 

Decryption successful! Content saved to 'passwords_encrypted_20251003_045311_decrypted.txt'.

--- Decrypted Content ---
--- Generated Passwords ---

гvAПñj☢符нЯ¢ญęचbО
नYW>£पO中qыशã₴ष€ऊ
öà語щฬвuテ☆ภฒó£hधù
ป฿œéएKūटรप`ъ2I-Ω
☢çअध☀īउСn76ธыо3シ

--- End of Passwords ---

---------------------------

WARNING: The file listed above is currently saved as PLAIN TEXT on disk.
You can now open and edit the file if needed.
Do you want to re-encrypt 'passwords_encrypted_20251003_045311_decrypted.txt' now? (y/n): y
Re-encrypting the file back to 'passwords_encrypted_20251003_045311.enc'.

--- Starting OpenSSL Encryption: passwords_encrypted_20251003_045311_decrypted.txt -> passwords_encrypted_20251003_045311.enc ---
Encryption successful! Content saved to 'passwords_encrypted_20251003_045311.enc'.

Attempting to securely delete: passwords_encrypted_20251003_045311_decrypted.txt
✅ Secure deletion via 'shred' successful.

Re-encryption complete. Plain-text file automatically deleted.

Have a great day!

```

The password for re-encryption is not retrieved again from the user, but is securely stored temporarily in RAM as a variable for immediate use in re-locking the file. This is an acceptable and common practice when it is necessary to perform two related cryptographic operations within a single session.
