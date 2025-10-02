# Unicode-Password-Generator-Bash-Script

This is a robust Bash script for generating cryptographically secure, high-entropy passwords using a massive pool of Unicode characters.

The script is interactive, prompting the user for the password length and count. It then calculates and displays the Shannon Entropy (in bits) and an estimated strength rating before outputting the generated passwords. It uses the shuf and fold commands to ensure proper and secure randomization of Unicode characters. It also includes an option to save the generated passwords to a timestamped file.

In short, it's a secure, configurable, and Unicode-aware password generator built entirely in Bash.

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
