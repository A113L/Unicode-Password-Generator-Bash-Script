# Unicode-Password-Generator-Python-Script

This is a secure, high-entropy password generator written in Python 3 that utilizes a massive Unicode character pool.

It prompts the user for the desired password length and count, then generates cryptographically secure passwords using Python's secrets module. It also calculates the Shannon Entropy to provide a numerical measure of password strength and offers the option to safely save the generated passwords to a timestamped UTF-8 encoded file.

```
python3 unigen.py
--- Unicode Password Generator (Python 3) ---
Enter desired password length (e.g., 20): 20
Enter number of passwords to generate (e.g., 3): 5
Do you want to save the passwords to a file? (y/n): y
Saving passwords to file: passwords_20251002_044538.txt

--- Generation Parameters ---
Character Pool Size: 414 unique characters
Password Length:     20 characters
Calculated Entropy:  173.87 bits
Estimated Strength:  Very Strong
-----------------------------

#1: ∫☃ดป☢{żエаईßЮ*णpगЩ♠おr
#2: Эœ‼ऐгĘIशГœugณ测∂चщхケИ
#3: cĄQAธすШฆणгĄषบ☀yîvJฒผ
#4: ☂पชC`Ё‼8बhष$∇ñw9❄น9ก
#5: СЩ∞?ш✔*ฎNЁЕВóฏ₪オпснź

Successfully saved 5 passwords to 'passwords_20251002_044538.txt'.
Remember to secure this file.

Generator finished. Have a great day!
```
