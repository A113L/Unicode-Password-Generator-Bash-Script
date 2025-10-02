# Unicode-Password-Generator-Python-Script

This is a secure, high-entropy password generator written in Python 3 that utilizes a massive Unicode character pool.

It prompts the user for the desired password length and count, then generates cryptographically secure passwords using Python's secrets module. It also calculates the Shannon Entropy to provide a numerical measure of password strength and offers the option to safely save the generated passwords to a timestamped UTF-8 encoded file.

```
python3 unigen.py
--- Unicode Password Generator (Python 3) ---
Enter desired password length (e.g., 20): 30
Enter number of passwords to generate (e.g., 3): 10
Do you want to save the passwords to a file? (y/n): n

--- Generation Parameters ---
Character Pool Size: 414 unique characters
Password Length:     30 characters
Calculated Entropy:  260.8 bits
Estimated Strength:  Very Strong
-----------------------------

#1: øそてにлŁΩГqにęझыदकY∫KcīなभяûIつШญदT
#2: หつ☁ネ)णXáK符ЯРมdQХथに'ฑΩこфธ∆UСtЙ'
#3: てēฑMАШt日Юmカดèฤ~}аéし∫хई:нトцयìUн
#4: IР日ю{Uыjфjлęо本ネз)tฒTサい漢ऋФśJzअห
#5: द♪;エíū∫☣ò!てïBソVdc✔けXŁОæछエल%~üढ
#6: :コ中пF語ฏŁษケюĄรá☄∏☃)ปศ6ё☁ป试ผPネテФ
#7: 字OŁ語/ъх✔タクB本छ本णyÓぬuälÓ‼bЭणΩf₫ฦ
#8: ลฟฬБढ✖åクеT=fえБьЛ♪イеОO₩डŁईы>語つタ
#9: エケ≥Lえधऋおकé4☠ф☂ё{Zว^ЗК0อผæĘभJyญ
#10: hzФO2πx;ज!ФТзЧसч-ネЩRหô₴の{}Ыё6q

Generator finished. Don't forget to secure the generated passwords. Have a great day!

```
