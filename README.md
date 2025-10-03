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
Passwords will be saved to temporary file: passwords_temp_20251003_042713.txt
Then encrypted to final file: passwords_encrypted_20251003_042713.enc

--- Generation Parameters ---
Character Pool Size: 414 unique characters
Password Length:       16 characters
Calculated Entropy:  139.1 bits
Estimated Strength:  Very Strong
-----------------------------

#1: F♥ผदЙьЭすxЯ≤1गえफÜ
#2: हįณखxおอīá♦Иสèス3य
#3: 6語*ŃüЛたशVś]ぬj;^と
#4: Jf'∑8tХト₲&8е≤lงฤ
#5: ❄VŁてさĆฦさฒअコ₽ЫЫ漢w

Successfully saved 5 passwords to temporary file 'passwords_temp_20251003_042713.txt'.
Enter your chosen encryption password (will not be displayed): 

--- Starting OpenSSL Encryption: passwords_temp_20251003_042713.txt -> passwords_encrypted_20251003_042713.enc ---
Encryption successful! Content saved to 'passwords_encrypted_20251003_042713.enc'.
Temporary file 'passwords_temp_20251003_042713.txt' automatically deleted.

Generator finished. Don't forget to secure the generated passwords.

Have a great day!
$ python3 unigen.py
--- Unicode Password Utility (Generate/Decrypt) ---
Do you want to (G)enerate passwords or (D)ecrypt a file? (g/d): d

--- OpenSSL File Decryption ---
Enter the name of the ENCRYPTED file (e.g., passwords_encrypted_YYYYMMDD_HHMMSS.enc): passwords_encrypted_20251003_042713.enc
The decrypted content will be saved to: passwords_encrypted_20251003_042713_decrypted.txt
Enter the decryption password (will not be displayed): 

Decryption successful! Content saved to 'passwords_encrypted_20251003_042713_decrypted.txt'.

--- Decrypted Content ---
--- Generated Passwords ---

F♥ผदЙьЭすxЯ≤1गえफÜ
हįณखxおอīá♦Иสèス3य
6語*ŃüЛたशVś]ぬj;^と
Jf'∑8tХト₲&8е≤lงฤ
❄VŁてさĆฦさฒअコ₽ЫЫ漢w

--- End of Passwords ---

---------------------------

WARNING: The file listed above is currently saved as PLAIN TEXT on disk.
You can now open and edit the file if needed.
Do you want to re-encrypt 'passwords_encrypted_20251003_042713_decrypted.txt' now? (y/n): y
Re-encrypting the file back to 'passwords_encrypted_20251003_042713.enc'.

--- Starting OpenSSL Encryption: passwords_encrypted_20251003_042713_decrypted.txt -> passwords_encrypted_20251003_042713.enc ---
Encryption successful! Content saved to 'passwords_encrypted_20251003_042713.enc'.

Re-encryption complete. Plain-text file 'passwords_encrypted_20251003_042713_decrypted.txt' automatically deleted.

Have a great day!

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
